/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "gtest/gtest.h"
#define QUIC_TEST_APIS
#include "msquichelper.h"
#include <future>
#include <atomic>
#include <mutex>
#include <chrono>
#include <array>
#include <vector>

constexpr uint16_t UdpPort = 4567;
const QUIC_BUFFER Alpn = { sizeof("connection") - 1, (uint8_t*)"connection" };

class ConnectionServer
{
public:
    QUIC_STATUS
        StreamHandler(
            HQUIC Stream,
            QUIC_STREAM_EVENT& Event
        )
    {
        switch (Event.Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            MsQuic->StreamSend(Stream, &QuicBuffer, 1, QUIC_SEND_FLAG_FIN, nullptr);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->StreamClose(Stream);
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS
        ConnectionHandler(
            HQUIC Connection,
            QUIC_CONNECTION_EVENT& Event
        )
    {
        switch (Event.Type) {
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            QUIC_STREAM_CALLBACK_HANDLER Handler = [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
                return ((ConnectionServer*)Context)->StreamHandler(Stream, *Event);
            };
            MsQuic->SetCallbackHandler(Event.PEER_STREAM_STARTED.Stream, (void*)Handler, this);
            break;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->ConnectionClose(Connection);
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS
        ListenerHandler(
            QUIC_LISTENER_EVENT& Event
        )
    {
        switch (Event.Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            Event.NEW_CONNECTION.SecurityConfig = SecConfig;
            QUIC_CONNECTION_CALLBACK_HANDLER Handler = [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
                return ((ConnectionServer*)Context)->ConnectionHandler(Connection, *Event);
            };
            MsQuic->SetCallbackHandler(Event.NEW_CONNECTION.Connection, (void*)Handler, this);
            break;
        }
        }
        return QUIC_STATUS_SUCCESS;
    }

    ConnectionServer(
        bool& WasSuccessful,
        int DataSize
    )
    {
        WasSuccessful = false;
        if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
            return;
        }

        // Create a registration
        QUIC_REGISTRATION_CONFIG Config{
            "ConnectionTestServer",
            QUIC_EXECUTION_PROFILE::QUIC_EXECUTION_PROFILE_LOW_LATENCY
        };
        if (QUIC_FAILED(MsQuic->RegistrationOpen(&Config, &Registration))) {
            return;
        }

        // Create a session
        if (QUIC_FAILED(MsQuic->SessionOpen(Registration, &Alpn, 1, this, &Session))) {
            return;
        }

        CertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
        if (!CertParams) {
            return;
        }

        std::promise<QUIC_SEC_CONFIG*> SecConfigCreatePromise;
        MsQuic->SecConfigCreate(Registration, (QUIC_SEC_CONFIG_FLAGS)CertParams->Flags, CertParams->Certificate, CertParams->Principal, &SecConfigCreatePromise, [](void* Context, QUIC_STATUS, QUIC_SEC_CONFIG* Config) {
            auto Promise = (std::promise<QUIC_SEC_CONFIG*>*)Context;
            Promise->set_value(Config);
            });
        SecConfig = SecConfigCreatePromise.get_future().get();
        if (!SecConfig) {
            return;
        }

        const uint16_t PeerStreamCount = 1;
        if (QUIC_FAILED(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount))) {
            return;
        }

        if (QUIC_FAILED(MsQuic->ListenerOpen(Session, [](HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
            return ((ConnectionServer*)Context)->ListenerHandler(*Event);
            }, this, &listener))) {
            return;
        }

        QUIC_ADDR Address = {};
        QuicAddrSetFamily(&Address, AF_UNSPEC);
        QuicAddrSetPort(&Address, UdpPort);

        if (QUIC_FAILED(MsQuic->ListenerStart(listener, &Address))) {
            return;
        }

        BufferData = std::make_unique<uint8_t[]>(DataSize);
        QuicBuffer.Buffer = BufferData.get();
        QuicBuffer.Length = DataSize;

        WasSuccessful = true;
    }

    ~ConnectionServer(
    )
    {
        if (MsQuic) {
            if (listener) {
                MsQuic->ListenerStop(listener);
                MsQuic->ListenerClose(listener);
            }
            if (SecConfig) {
                MsQuic->SecConfigDelete(SecConfig);
            }
            if (CertParams) {
                QuicPlatFreeSelfSignedCert(CertParams);
            }
            if (Session) {
                MsQuic->SessionShutdown(Session, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
                MsQuic->SessionClose(Session);
            }
            if (Registration) {
                MsQuic->RegistrationClose(Registration);
            }
            MsQuicClose(MsQuic);
        }
    }

private:
    const QUIC_API_TABLE* MsQuic = nullptr;
    HQUIC Registration = nullptr;
    HQUIC Session = nullptr;
    QUIC_SEC_CONFIG_PARAMS* CertParams = nullptr;
    QUIC_SEC_CONFIG* SecConfig = nullptr;
    HQUIC listener = nullptr;
    QUIC_BUFFER QuicBuffer{};
    std::unique_ptr<uint8_t[]> BufferData;
};

class ConnectionClient
{
public:

    QUIC_STATUS
        StreamEvent(
            HQUIC Stream,
            QUIC_STREAM_EVENT& Event
        )
    {
        switch (Event.Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->StreamClose(Stream);
            Stream = nullptr;
            MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS
        ConnectionEvent(
            HQUIC Connection,
            QUIC_CONNECTION_EVENT& Event
        )
    {
        switch (Event.Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
                return ((ConnectionClient*)Context)->StreamEvent(Stream, *Event);
                }, this, &Stream);

            MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE);
            MsQuic->StreamSend(Stream, &QuicBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->ConnectionClose(Connection); 
            Connection = nullptr;
            ConnectionHandled.set_value();
            break;
        }

        return QUIC_STATUS_SUCCESS;
    }

    ConnectionClient(
        bool& WasSuccessful,
        int DataSize
    )
    {
        WasSuccessful = false;
        if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
            return;
        }

        // Create a registration
        QUIC_REGISTRATION_CONFIG Config{
            "LoopbackTestClient",
            QUIC_EXECUTION_PROFILE::QUIC_EXECUTION_PROFILE_LOW_LATENCY
        };
        if (QUIC_FAILED(MsQuic->RegistrationOpen(&Config, &Registration))) {
            return;
        }

        // Create a session
        if (QUIC_FAILED(MsQuic->SessionOpen(Registration, &Alpn, 1, this, &Session))) {
            return;
        }

        BufferData = std::make_unique<uint8_t[]>(DataSize);
        QuicBuffer.Buffer = BufferData.get();
        QuicBuffer.Length = DataSize;

        WasSuccessful = true;

    }

    bool
        PerformTransaction(
            int TimeoutSeconds
        )
    {
        ConnectionHandled = std::promise<void>();
        // Create a connection
        if (QUIC_FAILED(MsQuic->ConnectionOpen(Session, [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
            return ((ConnectionClient*)Context)->ConnectionEvent(Connection, *Event);
            }, this, &Connection))) {
            return false;
        }

        const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
        if (QUIC_FAILED(MsQuic->SetParam(
            Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(CertificateValidationFlags), &CertificateValidationFlags))) {
            return false;
        }

        if (QUIC_FAILED(MsQuic->ConnectionStart(Connection, AF_UNSPEC, "127.0.0.1", UdpPort))) {
            return false;
        }

        auto Future = ConnectionHandled.get_future();
        return Future.wait_for(std::chrono::seconds(TimeoutSeconds)) == std::future_status::ready;
    }

    ~ConnectionClient(
    )
    {
        if (MsQuic) {
            if (Stream) {
                MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
            if (Connection) {
                MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
            }
            if (Session) {
                MsQuic->SessionShutdown(Session, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
                MsQuic->SessionClose(Session);
            }
            if (Registration) {
                MsQuic->RegistrationClose(Registration);
            }
            MsQuicClose(MsQuic);
        }
    }

private:

    const QUIC_API_TABLE* MsQuic = nullptr;
    HQUIC Registration = nullptr;
    HQUIC Session = nullptr;
    HQUIC Connection = nullptr;
    HQUIC Stream = nullptr;
    QUIC_BUFFER QuicBuffer{};
    std::unique_ptr<uint8_t[]> BufferData;
    std::atomic_bool KeepSending;
    std::promise<void> ConnectionHandled;

};

class ConnectionTestsTestFixture : public ::testing::TestWithParam<int> {

};

std::vector<std::pair<uint64_t, uint64_t>> ConnectionTimingData;


TEST_P(ConnectionTestsTestFixture, DISABLED_ConnectionFixedBufferTest) {
    bool WasSuccessful;
    ConnectionServer server{ WasSuccessful, GetParam() };
    ASSERT_TRUE(WasSuccessful);

    ConnectionClient client{ WasSuccessful, GetParam() };
    ASSERT_TRUE(WasSuccessful);

    int TransactionCount = 0;
    auto start = std::chrono::steady_clock::now();

    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        bool SendSuccessful = client.PerformTransaction(10);
        ASSERT_TRUE(SendSuccessful);
        TransactionCount++;
    }

    std::cout << "connections handled: " << TransactionCount << std::endl;
    ConnectionTimingData.emplace_back(std::make_pair((uint64_t)GetParam(), (uint64_t)TransactionCount));
}

INSTANTIATE_TEST_SUITE_P(
    ConnectionTests, ConnectionTestsTestFixture, ::testing::Values(2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
);
