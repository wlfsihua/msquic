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

constexpr uint16_t UdpPort = 4567;

class LoopbackServer {
public:
    QUIC_STATUS StreamHandler(HQUIC Stream, QUIC_STREAM_EVENT& Event) {
        switch (Event.Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            totalBytesReceived.fetch_add(Event.RECEIVE.TotalBufferLength);
            if ((Event.RECEIVE.Flags & QUIC_SEND_FLAG_FIN) != 0) {
                {
                    std::lock_guard lock{ timeMutex };
                    endTime = std::chrono::steady_clock::now();
                }
                streamFinishedSending.set_value();
            }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            apiTable->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            apiTable->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: 
            apiTable->StreamClose(Stream);
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS ConnectionHandler(HQUIC Connection, QUIC_CONNECTION_EVENT& Event) {
        switch (Event.Type) {
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            QUIC_STREAM_CALLBACK_HANDLER handler = [](HQUIC stream, void* context, QUIC_STREAM_EVENT* Event) {
                return ((LoopbackServer*)context)->StreamHandler(stream, *Event);
            };
            apiTable->SetCallbackHandler(Event.PEER_STREAM_STARTED.Stream, (void*)handler, this);
            {
                std::lock_guard lock{ timeMutex };
                startTime = std::chrono::steady_clock::now();
            }
            break;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            apiTable->ConnectionClose(Connection);
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS ListenerHandler(QUIC_LISTENER_EVENT& Event) {
        switch (Event.Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            Event.NEW_CONNECTION.SecurityConfig = secConfig;
            QUIC_CONNECTION_CALLBACK_HANDLER handler = [](HQUIC connection, void* context, QUIC_CONNECTION_EVENT* Event) {
                return ((LoopbackServer*)context)->ConnectionHandler(connection , *Event);
            };
            apiTable->SetCallbackHandler(Event.NEW_CONNECTION.Connection, (void*)handler, this);
            break;
        }
        }
        return QUIC_STATUS_SUCCESS;
    }

    LoopbackServer(bool& wasSuccessful) {
        wasSuccessful = false;
        if (QUIC_FAILED(MsQuicOpen(&apiTable))) {
            return;
        }

        // Create a registration
        QUIC_REGISTRATION_CONFIG config{
            "LoopbackTest",
            QUIC_EXECUTION_PROFILE::QUIC_EXECUTION_PROFILE_LOW_LATENCY
        };
        if (QUIC_FAILED(apiTable->RegistrationOpen(&config, &registration))) {
            return;
        }

        // Create a session
        const QUIC_BUFFER alpn = { sizeof("loopback") - 1, (uint8_t*)"loopback" };
        if (QUIC_FAILED(apiTable->SessionOpen(registration, &alpn, 1, this, &session))) {
            return;
        }

        certParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
        if (!certParams) {
            return;
        }

        std::promise<QUIC_SEC_CONFIG*> promise;
        apiTable->SecConfigCreate(registration, (QUIC_SEC_CONFIG_FLAGS)certParams->Flags, certParams->Certificate, certParams->Principal, &promise, [](void* context, QUIC_STATUS, QUIC_SEC_CONFIG* config) {
            auto promise = (std::promise<QUIC_SEC_CONFIG*>*)context;
            promise->set_value(config);
            });
        secConfig = promise.get_future().get();
        if (!secConfig) {
            return;
        }

        const uint16_t streamCount = 1;
        if (QUIC_FAILED(apiTable->SetParam(session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(streamCount), &streamCount))) {
            return;
        }

        if (QUIC_FAILED(apiTable->ListenerOpen(session, [](HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event) {
            return ((LoopbackServer*)Context)->ListenerHandler(*Event);
            }, this, &listener))) {
            return;
        }

        QUIC_ADDR Address = {};
        QuicAddrSetFamily(&Address, AF_UNSPEC);
        QuicAddrSetPort(&Address, UdpPort);

        if (QUIC_FAILED(apiTable->ListenerStart(listener, &Address))) {
            return;
        }

        wasSuccessful = true;
    }

    ~LoopbackServer() {
        if (apiTable) {
            if (listener) {
                apiTable->ListenerStop(listener);
                apiTable->ListenerClose(listener);
            }
            if (secConfig) {
                apiTable->SecConfigDelete(secConfig);
            }
            if (certParams) {
                QuicPlatFreeSelfSignedCert(certParams);
            }
            if (session) {
                apiTable->SessionShutdown(session, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
                apiTable->SessionClose(session);
            }
            if (registration) {
                apiTable->RegistrationClose(registration);
            }
            MsQuicClose(apiTable);
        }
    }

    bool WaitForStreamFinish() {
        return streamFinishedSending.get_future().wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    }

    uint64_t GetTotalBytesReceived() {
        return totalBytesReceived.load();
    }

    auto GetTimeDelta() {
        std::lock_guard lock{ timeMutex };
        return endTime - startTime;
    }

private:
    const QUIC_API_TABLE* apiTable = nullptr;
    HQUIC registration = nullptr;
    HQUIC session = nullptr;
    QUIC_SEC_CONFIG_PARAMS* certParams = nullptr;
    QUIC_SEC_CONFIG* secConfig = nullptr;
    HQUIC listener = nullptr;
    std::atomic_uint64_t totalBytesReceived{ 0 };
    std::mutex timeMutex;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    std::promise<void> streamFinishedSending;
};

class LoopbackClient {
public:

    QUIC_STATUS StreamEvent(HQUIC Stream, QUIC_STREAM_EVENT& Event) {
        switch (Event.Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            apiTable->StreamSend(stream, &buffer, 1, keepSending.load() ?  QUIC_SEND_FLAG_NONE : QUIC_SEND_FLAG_FIN, nullptr);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            apiTable->StreamClose(Stream);
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS ConnectionEvent(HQUIC Connection, QUIC_CONNECTION_EVENT& Event) {
        switch (Event.Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            connectionPromise.set_value();
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            apiTable->ConnectionClose(Connection);
            break;
        }

        return QUIC_STATUS_SUCCESS;
    }

    LoopbackClient(bool& wasSuccessful) {
        wasSuccessful = false;
        if (QUIC_FAILED(MsQuicOpen(&apiTable))) {
            return;
        }

        // Create a registration
        QUIC_REGISTRATION_CONFIG config{
            "LoopbackTest",
            QUIC_EXECUTION_PROFILE::QUIC_EXECUTION_PROFILE_LOW_LATENCY
        };
        if (QUIC_FAILED(apiTable->RegistrationOpen(&config, &registration))) {
            return;
        }

        // Create a session
        const QUIC_BUFFER alpn = { sizeof("loopback") - 1, (uint8_t*)"loopback" };
        if (QUIC_FAILED(apiTable->SessionOpen(registration, &alpn, 1, this, &session))) {
            return;
        }

        // Create a connection
        if (QUIC_FAILED(apiTable->ConnectionOpen(session, [](HQUIC Connection, void* context, QUIC_CONNECTION_EVENT* Event) {
            return ((LoopbackClient*)context)->ConnectionEvent(Connection, *Event);
            }, this, &connection))) {
            return;
        }

        if (QUIC_FAILED(apiTable->ConnectionStart(connection, AF_UNSPEC, "127.0.0.1", UdpPort))) {
            return;
        }
        auto future = connectionPromise.get_future();
        auto status = future.wait_for(std::chrono::seconds(2));
        if (status != std::future_status::ready) {
            return;
        }

        if (QUIC_FAILED(apiTable->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, [](HQUIC Stream, void* context, QUIC_STREAM_EVENT* Event) {
            return ((LoopbackClient*)context)->StreamEvent(Stream, *Event);
            }, this, &stream))) {
            return;
        }

        if (QUIC_FAILED(apiTable->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE))) {
            return;
        }

        wasSuccessful = true;
    }

    bool StartSend(int bufferSize) {
        bufferData = std::make_unique<uint8_t[]>(bufferSize);
        buffer.Buffer = bufferData.get();
        buffer.Length = bufferSize;
        keepSending = true;
        return QUIC_SUCCEEDED(apiTable->StreamSend(stream, &buffer, 1, QUIC_SEND_FLAG_NONE, nullptr));
    }

    void StopSend() {
        keepSending = false;
    }

    

    ~LoopbackClient() {
        if (apiTable) {
            if (stream) {
                apiTable->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
            if (connection) {
                apiTable->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
            }
            if (session) {
                apiTable->SessionShutdown(session, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
                apiTable->SessionClose(session);
            }
            if (registration) {
                apiTable->RegistrationClose(registration);
            }
            MsQuicClose(apiTable);
        }
    }

private:
    const QUIC_API_TABLE* apiTable = nullptr;
    HQUIC registration = nullptr;
    HQUIC session = nullptr;
    HQUIC connection = nullptr;
    HQUIC stream = nullptr;
    std::promise<void> connectionPromise;
    QUIC_BUFFER buffer{};
    std::unique_ptr<uint8_t[]> bufferData;
    std::atomic_bool keepSending;
    
};

class LoopbackTestsTestFixture : public ::testing::TestWithParam<int> {

};

TEST_P(LoopbackTestsTestFixture, LoopbackFixedBufferTest) {
    bool wasSuccessful;
    LoopbackServer server{ wasSuccessful };
    ASSERT_TRUE(wasSuccessful);

    LoopbackClient client{ wasSuccessful };
    ASSERT_TRUE(wasSuccessful);

    // Start send
    auto sendResult = client.StartSend(GetParam());
    std::cout << sendResult << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    client.StopSend();

    std::cout << "Server wait: " << server.WaitForStreamFinish() << std::endl;


    auto deltaTime = server.GetTimeDelta();
    auto bytes = server.GetTotalBytesReceived();

    auto bytesPerNanosecond = bytes / (double)deltaTime.count();
    auto bytesPerSecond = bytesPerNanosecond * 1000000000;

    std::cout << "bytes per second: " << bytesPerSecond << std::endl;
    std::cout << "bytes per nanosecond: " << bytesPerNanosecond << std::endl;
    std::cout << "total bytes: " << bytes << std::endl;
    std::cout << "nanoseconds: " << deltaTime.count() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
    LoopbackTests, LoopbackTestsTestFixture, ::testing::Values(2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
);