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
const QUIC_BUFFER Alpn = { sizeof("loopback") - 1, (uint8_t*)"loopback" };

class LoopbackServer
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
			TotalBytesReceived.fetch_add(Event.RECEIVE.TotalBufferLength);
			if ((Event.RECEIVE.Flags & QUIC_SEND_FLAG_FIN) != 0) {
				{
					std::lock_guard Lock{ TimeMutex };
					EndTime = std::chrono::steady_clock::now();
				}
				StreamFinishedSending.set_value();
			}
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
				return ((LoopbackServer*)Context)->StreamHandler(Stream, *Event);
			};
			MsQuic->SetCallbackHandler(Event.PEER_STREAM_STARTED.Stream, (void*)Handler, this);
			{
				std::lock_guard Lock{ TimeMutex };
				StartTime = std::chrono::steady_clock::now();
			}
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
				return ((LoopbackServer*)Context)->ConnectionHandler(Connection, *Event);
			};
			MsQuic->SetCallbackHandler(Event.NEW_CONNECTION.Connection, (void*)Handler, this);
			break;
		}
		}
		return QUIC_STATUS_SUCCESS;
	}

	LoopbackServer(
		bool& WasSuccessful
		)
	{
		WasSuccessful = false;
		if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
			return;
		}

		// Create a registration
		QUIC_REGISTRATION_CONFIG Config{
			"LoopbackTestServer",
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
			return ((LoopbackServer*)Context)->ListenerHandler(*Event);
			}, this, &listener))) {
			return;
		}

		QUIC_ADDR Address = {};
		QuicAddrSetFamily(&Address, AF_UNSPEC);
		QuicAddrSetPort(&Address, UdpPort);

		if (QUIC_FAILED(MsQuic->ListenerStart(listener, &Address))) {
			return;
		}

		WasSuccessful = true;
	}

	~LoopbackServer(
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

	bool
	WaitForStreamFinish(
		)
	{
		return StreamFinishedSending.get_future().wait_for(std::chrono::seconds(2)) == std::future_status::ready;
	}

	uint64_t
	GetTotalBytesReceived(
		)
	{
		return TotalBytesReceived.load();
	}

	auto
	GetTimeDelta(
		)
	{
		std::lock_guard lock{ TimeMutex };
		return EndTime - StartTime;
	}

private:
	const QUIC_API_TABLE* MsQuic = nullptr;
	HQUIC Registration = nullptr;
	HQUIC Session = nullptr;
	QUIC_SEC_CONFIG_PARAMS* CertParams = nullptr;
	QUIC_SEC_CONFIG* SecConfig = nullptr;
	HQUIC listener = nullptr;
	std::atomic_uint64_t TotalBytesReceived{ 0 };
	std::mutex TimeMutex;
	std::chrono::steady_clock::time_point StartTime;
	std::chrono::steady_clock::time_point EndTime;
	std::promise<void> StreamFinishedSending;
};

class LoopbackClient
{
public:

	QUIC_STATUS
	StreamEvent(
		HQUIC Stream, 
		QUIC_STREAM_EVENT& Event
	)
	{
		switch (Event.Type) {
		case QUIC_STREAM_EVENT_SEND_COMPLETE:
			MsQuic->StreamSend(Stream, &QuicBuffer, 1, KeepSending.load() ? QUIC_SEND_FLAG_NONE : QUIC_SEND_FLAG_FIN, nullptr);
			break;
		case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
			MsQuic->StreamClose(Stream);
		}
		return QUIC_STATUS_SUCCESS;
	}

	QUIC_STATUS 
	ConnectionEvent(
		HQUIC Connection,
		QUIC_CONNECTION_EVENT& Event
		)
	{
		std::cout << "Server: " << Event.Type << std::endl;
		switch (Event.Type) {
		case QUIC_CONNECTION_EVENT_CONNECTED:
			ConnectionPromise.set_value();
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
			MsQuic->ConnectionClose(Connection);
			break;
		}

		return QUIC_STATUS_SUCCESS;
	}

	LoopbackClient(
		bool& WasSuccessful
		)
	{
		WasSuccessful = false;
		if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
			return;
		}

		// Create a registration
		QUIC_REGISTRATION_CONFIG Config {
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

		// Create a connection
		if (QUIC_FAILED(MsQuic->ConnectionOpen(Session, [](HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
			return ((LoopbackClient*)Context)->ConnectionEvent(Connection, *Event);
			}, this, &Connection))) {
			return;
		}

		const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
		if (QUIC_FAILED(MsQuic->SetParam(
			Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
			sizeof(CertificateValidationFlags), &CertificateValidationFlags))) {
			return;
		}

		if (QUIC_FAILED(MsQuic->ConnectionStart(Connection, AF_UNSPEC, "127.0.0.1", UdpPort))) {
			return;
		}
		auto ConnectionFuture = ConnectionPromise.get_future();
		if (ConnectionFuture.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
			return;
		}

		if (QUIC_FAILED(MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) {
			return ((LoopbackClient*)Context)->StreamEvent(Stream, *Event);
			}, this, &Stream))) {
			return;
		}

		if (QUIC_FAILED(MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
			return;
		}

		WasSuccessful = true;
	}

	bool
	StartSend(
		int BufferSize
		)
	{
		BufferData = std::make_unique<uint8_t[]>(BufferSize);
		QuicBuffer.Buffer = BufferData.get();
		QuicBuffer.Length = BufferSize;
		KeepSending = true;
		return QUIC_SUCCEEDED(MsQuic->StreamSend(Stream, &QuicBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr));
	}

	void 
	StopSend(
		)
	{
		KeepSending = false;
	}

	~LoopbackClient(
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
	std::promise<void> ConnectionPromise;
	QUIC_BUFFER QuicBuffer{};
	std::unique_ptr<uint8_t[]> BufferData;
	std::atomic_bool KeepSending;

};

class LoopbackTestsTestFixture : public ::testing::TestWithParam<int> {

};

std::vector<std::pair<uint64_t, uint64_t>> timingData;

TEST_P(LoopbackTestsTestFixture, LoopbackFixedBufferTest) {
	bool WasSuccessful;
	LoopbackServer server{ WasSuccessful };
	ASSERT_TRUE(WasSuccessful);

	LoopbackClient client{ WasSuccessful };
	ASSERT_TRUE(WasSuccessful);

	// Start send
	bool SendSuccessful = client.StartSend(GetParam());
	ASSERT_TRUE(SendSuccessful);
	std::this_thread::sleep_for(std::chrono::seconds(10));
	client.StopSend();

	bool WaitSuccessful = server.WaitForStreamFinish();
	ASSERT_TRUE(WaitSuccessful);


	auto DeltaTime = server.GetTimeDelta();
	auto BytesReceived = server.GetTotalBytesReceived();

	auto BytesReceivedPerNanosecond = BytesReceived / (double)DeltaTime.count();
	auto BytesReceivedPerSecond = BytesReceivedPerNanosecond * 1000000000;

	std::cout << "bytes per second: " << BytesReceivedPerSecond << std::endl;
	std::cout << "bytes per nanosecond: " << BytesReceivedPerNanosecond << std::endl;
	std::cout << "total bytes: " << BytesReceived << std::endl;
	std::cout << "nanoseconds: " << DeltaTime.count() << std::endl;
	timingData.emplace_back(std::make_pair((uint64_t)GetParam(), (uint64_t)BytesReceivedPerSecond));
}

INSTANTIATE_TEST_SUITE_P(
	LoopbackTests, LoopbackTestsTestFixture, ::testing::Values(2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
);
