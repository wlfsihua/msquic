/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux and Darwin

--*/

#if defined(QUIC_PLATFORM_DARWIN)
#define __APPLE_USE_RFC_3542 1
// See netinet6/in6.h:46 for an explanation
#endif // QUIC_PLATFORM_DARWIN

#define _GNU_SOURCE
#include "platform_internal.h"

#if defined(QUIC_PLATFORM_LINUX)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <inttypes.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#elif defined(QUIC_PLATFORM_DARWIN)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/time.h>
#endif // QUIC_PLATFORM_DARWIN

#include "quic_platform_dispatch.h"

QUIC_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be TRUE.");
QUIC_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

#if !defined(MAX)
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

//
// TODO: Support batching.
//
#define QUIC_MAX_BATCH_SEND 1

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct QUIC_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    QUIC_POOL* OwningPool;

    //
    // The recv buffer used by MsQuic.
    //
    QUIC_RECV_DATAGRAM RecvPacket;

    //
    // Represents the address (source and destination) information of the
    // packet.
    //
    QUIC_TUPLE Tuple;

    //
    // Buffer that actually stores the UDP payload.
    //
    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // This follows the recv block.
    //
    // QUIC_RECV_PACKET RecvContext;

} QUIC_DATAPATH_RECV_BLOCK;

//
// Send context.
//

typedef struct QUIC_DATAPATH_SEND_CONTEXT {
    //
    // Indicates if the send should be bound to a local address.
    //
    BOOLEAN Bind;

    //
    // The local address to bind to.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address to send to.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Linkage to pending send list.
    //
    QUIC_LIST_ENTRY PendingSendLinkage;

    //
    // Indicates if the send is pending.
    //
    BOOLEAN Pending;

    //
    // The proc context owning this send context.
    //
    struct QUIC_DATAPATH_PROC_CONTEXT *Owner;

    //
    // BufferCount - The buffer count in use.
    //
    // CurrentIndex - The current index of the Buffers to be sent.
    //
    // Buffers - Send buffers.
    //
    // Iovs - IO vectors used for doing sends on the socket.
    //
    // TODO: Better way to reconcile layout difference
    // between QUIC_BUFFER and struct iovec?
    //
    size_t BufferCount;
    size_t CurrentIndex;
    QUIC_BUFFER Buffers[QUIC_MAX_BATCH_SEND];
    struct iovec Iovs[QUIC_MAX_BATCH_SEND];

} QUIC_DATAPATH_SEND_CONTEXT;

//
// Socket context.
//
typedef struct QUIC_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    QUIC_DATAPATH_BINDING* Binding;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

#if defined(QUIC_PLATFORM_LINUX)

    //
    // The cleanup event FD used by this socket context.
    //
    int CleanupFd;

    //
    // Used to register different event FD with epoll.
    //
#define QUIC_SOCK_EVENT_CLEANUP 0
#define QUIC_SOCK_EVENT_SOCKET  1
    uint8_t EventContexts[2];

#endif // QUIC_PLATFORM_LINUX

    //
    // Indicates if sends are waiting for the socket to be write ready.
    //
    BOOLEAN SendWaiting;

    //
    // The I/O vector for receive datagrams.
    //
    struct iovec RecvIov;

    //
    // The control buffer used in RecvMsgHdr.
    //
    char RecvMsgControl[CMSG_SPACE(sizeof(struct in6_pktinfo))];

    //
    // The buffer used to receive msg headers on socket.
    //
    struct msghdr RecvMsgHdr;

    //
    // The receive block currently being used for receives on this socket.
    //
    QUIC_DATAPATH_RECV_BLOCK* CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //
    QUIC_LIST_ENTRY PendingSendContextHead;

} QUIC_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct QUIC_DATAPATH_BINDING {

    //
    // A pointer to datapath object.
    //
    QUIC_DATAPATH* Datapath;

    //
    // The client context for this binding.
    //
    void *ClientContext;

    //
    // The local address for the binding.
    //
    QUIC_ADDR LocalAddress;

    //
    //  The remote address for the binding.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Synchronization mechanism for cleanup.
    //
    QUIC_RUNDOWN_REF Rundown;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Indicates the binding is shut down.
    //
    BOOLEAN Shutdown : 1;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Set of socket contexts one per proc.
    //
    QUIC_SOCKET_CONTEXT SocketContexts[];

} QUIC_DATAPATH_BINDING;

//
// A per processor datapath context.
//
typedef struct QUIC_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //
    QUIC_DATAPATH* Datapath;

#if defined(QUIC_PLATFORM_LINUX)
    //
    // The Epoll FD for this proc context.
    //
    int EpollFd;

    //
    // The event FD for this proc context.
    //
    int EventFd;

#elif defined(QUIC_PLATFORM_DARWIN)

    //
    // The Kqueue FD for this proc context.
    //
    int KqueueFd;

#endif // QUIC_PLATFORM_DARWIN

    //
    // The index of the context in the datapath's array.
    //
    uint32_t Index;

    //
    // The epoll wait thread.
    // Currently epoll & kqueue thread; 
    //
    QUIC_THREAD WorkerThread;

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    QUIC_POOL RecvBlockPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //
    QUIC_POOL SendBufferPool;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    QUIC_POOL SendContextPool;

} QUIC_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct QUIC_DATAPATH {
    //
    // If datapath is shutting down.
    //
    BOOLEAN volatile Shutdown;

    //
    // The max send batch size.
    // TODO: See how send batching can be enabled.
    //
    uint8_t MaxSendBatchSize;

    //
    // A reference rundown on the datapath binding.
    //
    QUIC_RUNDOWN_REF BindingsRundown;

    //
    // The MsQuic receive handler.
    //
    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvHandler;

    //
    // The MsQuic unreachable handler.
    //
    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachHandler;

    //
    // The length of recv context used by MsQuic.
    //
    size_t ClientRecvContextLength;

    //
    // The proc count to create per proc datapath state.
    //
    uint32_t ProcCount;

    //
    // The per proc datapath contexts.
    //
    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[];

} QUIC_DATAPATH;

QUIC_STATUS
QuicDataPathBindingSend(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

void*
QuicDataPathWorkerThread(
    _In_ void* Context
    );

QUIC_STATUS
QuicProcessorContextInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t Index,
    _Out_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int EpollFd = INVALID_SOCKET_FD;
    int EventFd = INVALID_SOCKET_FD;
    int Ret = 0;
    uint32_t RecvPacketLength = 0;
    BOOLEAN EventFdAdded = FALSE;

    QUIC_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(QUIC_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    ProcContext->Index = Index;
    QuicPoolInitialize(TRUE, RecvPacketLength, &ProcContext->RecvBlockPool);
    QuicPoolInitialize(TRUE, MAX_UDP_PAYLOAD_LENGTH, &ProcContext->SendBufferPool);
    QuicPoolInitialize(
        TRUE,
        sizeof(QUIC_DATAPATH_SEND_CONTEXT),
        &ProcContext->SendContextPool);

#if defined(QUIC_PLATFORM_LINUX)

    EpollFd = epoll_create1(EPOLL_CLOEXEC);
    if (EpollFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "epoll_create1(EPOLL_CLOEXEC) failed");
        goto Exit;
    }

    EventFd = eventfd(0, EFD_CLOEXEC);
    if (EventFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "eventfd failed");
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = NULL
        }
    };

    Ret = epoll_ctl(EpollFd, EPOLL_CTL_ADD, EventFd, &EvtFdEpEvt);
    if (Ret != 0) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "epoll_ctl(EPOLL_CTL_ADD) failed");
        goto Exit;
    }

    EventFdAdded = TRUE;

    ProcContext->Datapath = Datapath;
    ProcContext->EpollFd = EpollFd;
    ProcContext->EventFd = EventFd;

#elif defined(QUIC_PLATFORM_DARWIN)

    int KqueueFd = kqueue();

    if (KqueueFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "kqueue() failed");
        goto Exit;
    }

    ProcContext->Datapath = Datapath;
    ProcContext->KqueueFd = KqueueFd;

#endif // QUIC_PLATFORM_DARWIN

    //
    // Starting the thread must be done after the rest of the ProcContext
    // members have been initialized. Because the thread start routine accesses
    // ProcContext members.
    //

    QUIC_THREAD_CONFIG ThreadConfig = {
        0,
        0,
        NULL,
        QuicDataPathWorkerThread,
        ProcContext
    };

    Status = QuicThreadCreate(&ThreadConfig, &ProcContext->WorkerThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicThreadCreate failed");
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {

#if defined(QUIC_PLATFORM_LINUX)
        if (EventFdAdded) {
            epoll_ctl(EpollFd, EPOLL_CTL_DEL, EventFd, NULL);
        }
        if (EventFd != INVALID_SOCKET_FD) {
            close(EventFd);
        }
        if (EpollFd != INVALID_SOCKET_FD) {
            close(EpollFd);
        }

#elif defined(QUIC_PLATFORM_DARWIN)

        if (KqueueFd != INVALID_SOCKET_FD) {
            close(KqueueFd);
        }

#endif // QUIC_PLATFORM_DARWIN

        QuicPoolUninitialize(&ProcContext->RecvBlockPool);
        QuicPoolUninitialize(&ProcContext->SendBufferPool);
        QuicPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}

void
QuicProcessorContextUninitialize(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{

#if defined(QUIC_PLATFORM_LINUX)

    const eventfd_t Value = 1;
    eventfd_write(ProcContext->EventFd, Value);
    QuicThreadWait(&ProcContext->WorkerThread);
    QuicThreadDelete(&ProcContext->WorkerThread);

    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, ProcContext->EventFd, NULL);
    close(ProcContext->EventFd);
    close(ProcContext->EpollFd);

#elif defined(QUIC_PLATFORM_DARWIN)

    // TODO: wait till the worker thread shuts down
    close(ProcContext->KqueueFd);
    
#endif

    QuicPoolUninitialize(&ProcContext->RecvBlockPool);
    QuicPoolUninitialize(&ProcContext->SendBufferPool);
    QuicPoolUninitialize(&ProcContext->SendContextPool);
}

QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDataPath
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathInitialize(
            ClientRecvContextLength,
            RecvCallback,
            UnreachableCallback,
            NewDataPath);
#else
    if (RecvCallback == NULL ||
        UnreachableCallback == NULL ||
        NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    size_t DatapathLength =
        sizeof(QUIC_DATAPATH) +
            QuicProcMaxCount() * sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    QUIC_DATAPATH* Datapath = (QUIC_DATAPATH*)QUIC_ALLOC_PAGED(DatapathLength);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(Datapath, DatapathLength);
    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
#if defined(QUIC_PLATFORM_LINUX)
    Datapath->ProcCount = QuicProcMaxCount();
#elif defined(QUIC_PLATFORM_DARWIN)
    Datapath->ProcCount = 1;
#endif 
    Datapath->MaxSendBatchSize = QUIC_MAX_BATCH_SEND;
    QuicRundownInitialize(&Datapath->BindingsRundown);

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        Status = QuicProcessorContextInitialize(Datapath, i, &Datapath->ProcContexts[i]);
        if (QUIC_FAILED(Status)) {
            Datapath->Shutdown = TRUE;
            for (uint32_t j = 0; j < i; j++) {
                QuicProcessorContextUninitialize(&Datapath->ProcContexts[j]);
            }
            goto Exit;
        }
    }

    *NewDataPath = Datapath;
    Datapath = NULL;

Exit:

    if (Datapath != NULL) {
        QuicRundownUninitialize(&Datapath->BindingsRundown);
        QUIC_FREE(Datapath);
    }

    return Status;
#endif
}

void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathUninitialize(Datapath);
#else
    QuicRundownReleaseAndWait(&Datapath->BindingsRundown);

    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        QuicProcessorContextUninitialize(&Datapath->ProcContexts[i]);
    }

    QuicRundownUninitialize(&Datapath->BindingsRundown);
    QUIC_FREE(Datapath);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return 0;
}

BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathIsPaddingPreferred(Datapath);
#else
    UNREFERENCED_PARAMETER(Datapath);
    //
    // The windows implementation returns TRUE only if GSO is supported and
    // this DAL implementation doesn't support GSO currently.
    //
    return FALSE;
#endif
}

QUIC_DATAPATH_RECV_BLOCK*
QuicDataPathAllocRecvBlock(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t ProcIndex
    )
{
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QuicPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvBlockPool);
    if (RecvBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_RECV_BLOCK",
            0);
    } else {
        QuicZeroMemory(RecvBlock, sizeof(*RecvBlock));
        RecvBlock->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvBlockPool;
        RecvBlock->RecvPacket.Buffer = RecvBlock->Buffer;
        RecvBlock->RecvPacket.Allocated = TRUE;
    }
    return RecvBlock;
}

void
QuicDataPathPopulateTargetAddress(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ QUIC_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    QuicZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //

        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;

        if (Family == AF_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //

            SockAddrIn->sin_family = AF_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        } else {
            Address->Ipv6 = *SockAddrIn6;
            return;
        }
    } else if (AddrInfo->ai_addr->sa_family == AF_INET) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        QUIC_FRE_ASSERT(FALSE);
    }
}

QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathResolveAddress(Datapath, HostName, Address);
#else
    UNREFERENCED_PARAMETER(Datapath);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = QUIC_STATUS_DNS_RESOLUTION_ERROR;

Exit:

    return Status;
#endif
}

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//

#if defined(QUIC_PLATFORM_LINUX)

QUIC_STATUS
QuicSocketContextInitialize(
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    QUIC_ADDR MappedRemoteAddress = {0};
    socklen_t AssignedLocalAddressLength = 0;

    QUIC_DATAPATH_BINDING* Binding = SocketContext->Binding;

    for (uint32_t i = 0; i < ARRAYSIZE(SocketContext->EventContexts); ++i) {
        SocketContext->EventContexts[i] = i;
    }

    SocketContext->CleanupFd = eventfd(0, EFD_CLOEXEC);
    if (SocketContext->CleanupFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "eventfd failed");
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_CLEANUP]
        }
    };

    if (epoll_ctl(
            ProcContext->EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->CleanupFd,
            &EvtFdEpEvt) != 0) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "epoll_ctl(EPOLL_CTL_ADD) failed");
        goto Exit;
    }

    //
    // Create datagram socket.
    //
    SocketContext->SocketFd =
        socket(
            AF_INET6,
            SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, // TODO check if SOCK_CLOEXEC is required?
            IPPROTO_UDP);
    if (SocketContext->SocketFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }

    //
    // Set dual (IPv4 & IPv6) socket mode.
    //
    Option = FALSE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_V6ONLY) failed");
        goto Exit;
    }

    //
    // Set DON'T FRAG socket option.
    //

    //
    // Windows: setsockopt IPPROTO_IP IP_DONTFRAGMENT TRUE.
    // Linux: IP_DONTFRAGMENT option is not available. IPV6_MTU_DISCOVER is the
    // apparent alternative.
    // TODO: Verify this.
    //
    Option = IP_PMTUDISC_DO;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_MTU_DISCOVER) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_DONTFRAG,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_DONTFRAG) failed");
        goto Exit;
    }

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //

    //
    // Windows: setsockopt IPPROTO_IPV6 IPV6_PKTINFO TRUE.
    // Android: Returns EINVAL. IPV6_PKTINFO option is not present in documentation.
    // IPV6_RECVPKTINFO seems like is the alternative.
    // TODO: Check if this works as expected?
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVPKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVPKTINFO) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_PKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_PKTINFO) failed");
        goto Exit;
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //
    Option = INT32_MAX;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_RCVBUF,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_RCVBUF) failed");
        goto Exit;
    }

    //
    // The port is shared across processors.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_REUSEADDR) failed");
        goto Exit;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            (const struct sockaddr*)&Binding->LocalAddress,
            sizeof(Binding->LocalAddress));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "bind failed");
        goto Exit;
    }

    if (RemoteAddress != NULL) {
        QuicZeroMemory(&MappedRemoteAddress, sizeof(MappedRemoteAddress));
        QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        Result =
            connect(
                SocketContext->SocketFd,
                (const struct sockaddr*)&MappedRemoteAddress,
                sizeof(MappedRemoteAddress));

        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "connect failed");
            goto Exit;
        }
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
    Result =
        getsockname(
            SocketContext->SocketFd,
            (struct sockaddr *)&Binding->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

#elif defined(QUIC_PLATFORM_DARWIN)

QUIC_STATUS
QuicSocketContextInitialize(
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    QUIC_ADDR MappedRemoteAddress = { };
    socklen_t AssignedLocalAddressLength = 0;

    QUIC_DATAPATH_BINDING* Binding = SocketContext->Binding;

    //
    // Create datagram socket.
    //

    sa_family_t af_family = Binding->LocalAddress.Ip.sa_family;

    SocketContext->SocketFd = socket(af_family, SOCK_DGRAM, 0);

    if (SocketContext->SocketFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }

    socklen_t AddrSize = 0;

    if (af_family == AF_INET) {
        AddrSize = sizeof(struct sockaddr_in);

        Option = TRUE;
        Result =
            setsockopt(SocketContext->SocketFd, IPPROTO_IP, IP_PKTINFO, &Option, sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    Status,
                    "setsockopt(IP_PKTINFO) failed");
            goto Exit;
        }
    }
    else {
        AddrSize = sizeof(struct sockaddr_in6);

        Option = TRUE;
        Result = 
            setsockopt(SocketContext->SocketFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &Option, sizeof(Option));
        Option = TRUE;
        Result =
            setsockopt(SocketContext->SocketFd, IPPROTO_IPV6, IPV6_PKTINFO, &Option, sizeof(Option));
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //
    Option = INT32_MAX / 400;
    // This is the largest value that actually works. I don't know why.
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_RCVBUF,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(SO_RCVBUF) failed");
        goto Exit;
    }

    //
    // The port is shared across processors.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_REUSEADDR) failed");
        goto Exit;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            (const struct sockaddr *)&Binding->LocalAddress,
            AddrSize);
    
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "bind() failed");
        goto Exit;
    }

    if (RemoteAddress != NULL) {
        // XXX: Don't map v4-to-v6 addresses for now.
        // QuicZeroMemory(&MappedRemoteAddress, sizeof(MappedRemoteAddress));
        // QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        Result =
            connect(
                SocketContext->SocketFd,
                (const struct sockaddr *)RemoteAddress,
                AddrSize);

        if (Result == SOCKET_ERROR) {
            __asm__("int3");
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "connect failed");
            goto Exit;
        }
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    AssignedLocalAddressLength = sizeof(struct sockaddr);
    Result =
        getsockname(
            SocketContext->SocketFd,
            (struct sockaddr *)&Binding->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

#endif // QUIC_PLATFORM_DARWIN

void
QuicSocketContextUninitialize(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{

#if defined(QUIC_PLATFORM_LINUX)

    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

    const eventfd_t Value = 1;
    eventfd_write(SocketContext->CleanupFd, Value);

#elif defined(QUIC_PLATFORM_DARWIN)
 
    // XXX: Documentation says shutdown(Sockfd, SHUT_RD) is enough to wake up the kqueue
    // However, this seems to only happen after we've recieved some data..
    // So we use EVFILT_USER to indicate that we want to destroy this socket
    // context, and to wake up the worker thread. Perhaps we should pass an
    // explicit CLOSE message to the worker thread, but for now, any
    // EVFILT_USER event is a shutdown.
    // shutdown(SocketContext->SocketFd, SHUT_RDWR);
    
    struct kevent EvSet[2] = { };
    EV_SET(&EvSet[0], SocketContext->SocketFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, (void *)SocketContext);
    EV_SET(&EvSet[1], SocketContext->SocketFd, EVFILT_READ, EV_DELETE, 0, 0, (void *)SocketContext);
    kevent(ProcContext->KqueueFd, EvSet, 2, NULL, 0, NULL);

#endif // QUIC_PLATFORM_DARWIN
}

void
QuicSocketContextUninitializeComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    if (SocketContext->CurrentRecvBlock != NULL) {
        QuicDataPathBindingReturnRecvDatagrams(&SocketContext->CurrentRecvBlock->RecvPacket);
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendContextHead)) {
        QuicDataPathBindingFreeSendContext(
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendContextHead),
                QUIC_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage));
    }

#if defined(QUIC_PLATFORM_LINUX)

    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->CleanupFd, NULL);
    close(SocketContext->CleanupFd);
    close(SocketContext->SocketFd);

#elif defined(QUIC_PLATFORM_DARWIN)

    close(SocketContext->SocketFd);

#endif // QUIC_PLATFORM_DARWIN 

    QuicRundownRelease(&SocketContext->Binding->Rundown);
}

QUIC_STATUS
QuicSocketContextPrepareReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock == NULL) {
#if defined(QUIC_PLATFORM_LINUX)
        SocketContext->CurrentRecvBlock =
            QuicDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                QuicProcCurrentNumber());
#elif defined(QUIC_PLATFORM_DARWIN)
        SocketContext->CurrentRecvBlock =
            QuicDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                0);
#endif
        if (SocketContext->CurrentRecvBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "QUIC_DATAPATH_RECV_BLOCK",
                0);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.BufferLength = SocketContext->RecvIov.iov_len;
    SocketContext->CurrentRecvBlock->RecvPacket.Tuple = (QUIC_TUPLE*)&SocketContext->CurrentRecvBlock->Tuple;

    QuicZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    QuicZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress);
    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;
    SocketContext->RecvMsgHdr.msg_control = SocketContext->RecvMsgControl;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControl);
    SocketContext->RecvMsgHdr.msg_flags = 0;

    return QUIC_STATUS_SUCCESS;
}

#if defined(QUIC_PLATFORM_LINUX)

QUIC_STATUS
QuicSocketContextStartReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ int EpollFd
    )
{
    QUIC_STATUS Status = QuicSocketContextPrepareReceive(SocketContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    struct epoll_event SockFdEpEvt = {
        .events = EPOLLIN | EPOLLET,
        .data = {
            .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_SOCKET]
        }
    };

    int Ret =
        epoll_ctl(
            EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->SocketFd,
            &SockFdEpEvt);
    if (Ret != 0) {
        Status = Ret;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "epoll_ctl failed");
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

#elif defined(QUIC_PLATFORM_DARWIN)

QUIC_STATUS
QuicSocketContextStartReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ int KqueueFd
    )
{
    QUIC_STATUS Status = QuicSocketContextPrepareReceive(SocketContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    struct kevent evSet = { };
    EV_SET(&evSet, SocketContext->SocketFd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, (void *)SocketContext);
    if (kevent(KqueueFd, &evSet, 1, NULL, 0, NULL) < 0)  {
        QUIC_DBG_ASSERT(0);
        // Should be QUIC_STATUS_KQUEUE_ERROR
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "kevent(..., sockfd EV_ADD, ...) failed");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

#endif // QUIC_PLATFORM_DARWIN

void
QuicSocketContextRecvComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ ssize_t BytesTransferred
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QUIC_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);
    QUIC_RECV_DATAGRAM* RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;

    BOOLEAN FoundLocalAddr = FALSE;
    QUIC_ADDR* LocalAddr = &RecvPacket->Tuple->LocalAddress;
    QUIC_ADDR* RemoteAddr = &RecvPacket->Tuple->RemoteAddress;

    // Currently aren't using dual-stack socket on darwin. Don't map v4.
#if defined(QUIC_PLATFORM_LINUX)
    QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);
#endif

    struct cmsghdr *CMsg;
    for (CMsg = CMSG_FIRSTHDR(&SocketContext->RecvMsgHdr);
         CMsg != NULL;
         CMsg = CMSG_NXTHDR(&SocketContext->RecvMsgHdr, CMsg)) {

        if (CMsg->cmsg_level == IPPROTO_IPV6 &&
            CMsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            LocalAddr->Ip.sa_family = AF_INET6;
            LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
            LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
            // Currently aren't using dual-stack socket on darwin. Don't map v4.
#if defined(QUIC_PLATFORM_LINUX)
            QuicConvertFromMappedV6(LocalAddr, LocalAddr);
#endif

            LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
            FoundLocalAddr = TRUE;
            break;
        }

        if (CMsg->cmsg_level == IPPROTO_IP && CMsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
            LocalAddr->Ip.sa_family = AF_INET;
            LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
            LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
            LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
            FoundLocalAddr = TRUE;
            break;
        }
    }

    QUIC_FRE_ASSERT(FoundLocalAddr);

    QuicTraceEvent(
        DatapathRecv,
        "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!SOCKADDR! Dst=%!SOCKADDR!",
        SocketContext->Binding,
        (uint32_t)BytesTransferred,
        (uint32_t)BytesTransferred,
        LOG_ADDR_LEN(*LocalAddr),
        LOG_ADDR_LEN(*RemoteAddr),
        (uint8_t*)LocalAddr,
        (uint8_t*)RemoteAddr);

    QUIC_DBG_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    RecvPacket->PartitionIndex = ProcContext->Index;

    QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->RecvHandler);
    SocketContext->Binding->Datapath->RecvHandler(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RecvPacket);

    Status = QuicSocketContextPrepareReceive(SocketContext);

    //
    // Prepare can only fail under low memory condition. Treat it as a fatal
    // error.
    //
    QUIC_FRE_ASSERT(QUIC_SUCCEEDED(Status));
}

QUIC_STATUS
QuicSocketContextPendSend(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (!SocketContext->SendWaiting) {

#if defined(QUIC_PLATFORM_LINUX)

        struct epoll_event SockFdEpEvt = {
            .events = EPOLLIN | EPOLLOUT | EPOLLET,
            .data = {
                .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_SOCKET]
            }
        };

        int Ret =
            epoll_ctl(
                ProcContext->EpollFd,
                EPOLL_CTL_MOD,
                SocketContext->SocketFd,
                &SockFdEpEvt);
        if (Ret != 0) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                errno,
                "epoll_ctl failed");
            return errno;
        }

#elif defined(QUIC_PLATFORM_DARWIN)

        // We have to enable EVFILT_WRITE notifications here, since there's
        // basically nowhere else to try and empty the send queue except the
        // worker thread, and there's the possibility that the worker thread
        // won't wake up fast enough.

        // We can try to EV_ONESHOT this, s.t. we only get woken up for this
        // once, attempt to empty the sendqueue, and if it fails, then add it
        // again as oneshot.
        //
        // The alternate option is to add it normally, so we constantly get
        // woken up for it, and after N missed writes (i.e. the kernel had room
        // and we had nothing to write), we can turn it off.
        //
        // Or we could do some mix of both, and try to recognize how often
        // we're missing writes or re-pending writes.
        
        // For now, we'll do the most naïve thing, and oneshot it everytime we
        // hit this function.
        
        struct kevent Event = { };
        EV_SET(&Event, SocketContext->SocketFd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, (void *)SocketContext);
        kevent(ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);

#endif // QUIC_PLATFORM_DARWIN

        if (LocalAddress != NULL) {
            QuicCopyMemory(
                &SendContext->LocalAddress,
                LocalAddress,
                sizeof(*LocalAddress));
            SendContext->Bind = TRUE;
        }

        QuicCopyMemory(
            &SendContext->RemoteAddress,
            RemoteAddress,
            sizeof(*RemoteAddress));

        SocketContext->SendWaiting = TRUE;
    }

    if (SendContext->Pending) {
        //
        // This was a send that was already pending, so we need to add it back
        // to the head of the queue.
        //
        QuicListInsertHead(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
    } else {
        //
        // This is a new send that wasn't previously pended. Add it to the end
        // of the queue.
        //
        QuicListInsertTail(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
        SendContext->Pending = TRUE;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicSocketContextSendPending(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (SocketContext->SendWaiting) {

#if defined(QUIC_PLATFORM_LINUX)

        struct epoll_event SockFdEpEvt = {
            .events = EPOLLIN | EPOLLET,
            .data = {
                .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_SOCKET]
            }
        };

        int Ret =
            epoll_ctl(
                ProcContext->EpollFd,
                EPOLL_CTL_MOD,
                SocketContext->SocketFd,
                &SockFdEpEvt);
        if (Ret != 0) {
            Status = Ret;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                Status,
                "epoll_ctl failed");
            goto Exit;
        }

#endif // QUIC_PLATFORM_LINUX

        SocketContext->SendWaiting = FALSE;
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendContextHead)) {
        // This is .. funky?
        // It seems possible that this will queue up the send again and we'll
        // just spin until the kernel accepts it...
 
        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendContextHead),
                QUIC_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage);

        Status =
            QuicDataPathBindingSend(
                SocketContext->Binding,
                SendContext->Bind ? &SendContext->LocalAddress : NULL,
                &SendContext->RemoteAddress,
                SendContext);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

        if (SocketContext->SendWaiting) {
            break;
        }
    }

Exit:

    return Status;
}

#if defined(QUIC_PLATFORM_LINUX)

void
QuicSocketContextProcessEvent(
    _In_ void* EventPtr,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ int Events
    )
{
    uint8_t EventType = *(uint8_t*)EventPtr;
    QUIC_SOCKET_CONTEXT* SocketContext =
        ((QUIC_SOCKET_CONTEXT*)( \
            (uint8_t*)(EventPtr) - \
            (size_t)(&((QUIC_SOCKET_CONTEXT*)0)->EventContexts) -
            EventType));

    if (EventType == QUIC_SOCK_EVENT_CLEANUP) {
        QUIC_DBG_ASSERT(SocketContext->Binding->Shutdown);
        QuicSocketContextUninitializeComplete(SocketContext, ProcContext);
        return;
    }

    QUIC_DBG_ASSERT(EventType == QUIC_SOCK_EVENT_SOCKET);

    if (EPOLLERR & Events) {
        int ErrNum = 0;
        socklen_t OptLen = sizeof(ErrNum);
        ssize_t Ret =
            getsockopt(
                SocketContext->SocketFd,
                SOL_SOCKET,
                SO_ERROR,
                &ErrNum,
                &OptLen);
        if (Ret < 0) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                errno,
                "getsockopt(SO_ERROR) failed");
        } else {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                ErrNum,
                "Socket error event");

            //
            // Send unreachable notification to MsQuic if any related
            // errors were received.
            //
            if (ErrNum == ECONNREFUSED ||
                ErrNum == EHOSTUNREACH ||
                ErrNum == ENETUNREACH) {
                SocketContext->Binding->Datapath->UnreachHandler(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    &SocketContext->Binding->RemoteAddress);
            }
        }
    }

    if (EPOLLIN & Events) {
        while (TRUE) {
            QUIC_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);

            ssize_t Ret =
                recvmsg(
                    SocketContext->SocketFd,
                    &SocketContext->RecvMsgHdr,
                    0);
            if (Ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[ udp][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "recvmsg failed");
                }
                break;
            } else {
                QuicSocketContextRecvComplete(SocketContext, ProcContext, Ret);
            }
        }
    }

    if (EPOLLOUT & Events) {
        QuicSocketContextSendPending(SocketContext, ProcContext);
    }
}

#elif defined(QUIC_PLATFORM_DARWIN)

void
QuicSocketContextProcessEvent(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ struct kevent *Event
    )
{
    QUIC_DBG_ASSERT(Event->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));

    QUIC_SOCKET_CONTEXT *SocketContext = (QUIC_SOCKET_CONTEXT *)Event->udata;

    if (Event->filter == EVFILT_USER || Event->flags & EV_EOF) {
        QUIC_DBG_ASSERT(SocketContext->Binding->Shutdown);
        QuicSocketContextUninitializeComplete(SocketContext, ProcContext);
        return;
    }

    else if (Event->filter == EVFILT_READ) {
        int Ret = recvmsg(SocketContext->SocketFd, &SocketContext->RecvMsgHdr, 0);
        if (Ret != -1)
            QuicSocketContextRecvComplete(SocketContext, ProcContext, Ret);
    }

    else if (Event->filter == EVFILT_WRITE) {
        QuicSocketContextSendPending(SocketContext, ProcContext);
    }
}

#endif // QUIC_PLATFORM_DARWIN

//
// Datapath binding interface.
//

QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** NewBinding
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingCreate(
            Datapath,
            LocalAddress,
            RemoteAddress,
            RecvCallbackContext,
            NewBinding);
#else
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    uint32_t SocketCount = Datapath->ProcCount; // TODO - Only use 1 for client (RemoteAddress != NULL) bindings?
    size_t BindingLength =
        sizeof(QUIC_DATAPATH_BINDING) +
        SocketCount * sizeof(QUIC_SOCKET_CONTEXT);

    QUIC_DATAPATH_BINDING* Binding =
        (QUIC_DATAPATH_BINDING*)QUIC_ALLOC_PAGED(BindingLength);
    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_BINDING",
            BindingLength);
        goto Exit;
    }

    QuicTraceLogInfo(
        DatapathCreate,
        "[ udp][%p] Created.",
        Binding);

    QuicZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->Mtu = QUIC_MAX_MTU;
    QuicRundownInitialize(&Binding->Rundown);
#if defined(QUIC_PLATFORM_LINUX)
    if (LocalAddress) {
        QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = AF_INET6;
    }
#elif defined(QUIC_PLATFORM_DARWIN)
    if (LocalAddress) {
        memcpy(&Binding->LocalAddress, LocalAddress, sizeof(QUIC_ADDR));
        // QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else if (RemoteAddress) {
        // We have no local address, but we have a remote address. 
        // Let's match up AF types with the remote.
        Binding->LocalAddress.Ip.sa_family = RemoteAddress->Ip.sa_family;
    } else {
        // This indicates likely that the application wants a listener with a random port.
        // Since we can't dual-stack socket, fall back to AF_INET6
        Binding->LocalAddress.Ip.sa_family = AF_INET6;
    }

#endif // QUIC_PLATFORM_DARWIN

    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET_FD;
        Binding->SocketContexts[i].RecvIov.iov_len =
            Binding->Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
        QuicListInitializeHead(&Binding->SocketContexts[i].PendingSendContextHead);
        QuicRundownAcquire(&Binding->Rundown);
    }

    QuicRundownAcquire(&Datapath->BindingsRundown);

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            QuicSocketContextInitialize(
                &Binding->SocketContexts[i],
                &Datapath->ProcContexts[i],
                LocalAddress,
                RemoteAddress);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

#if defined(QUIC_PLATFORM_LINUX)
    QuicConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;
#endif // QUIC_PLATFORM_LINUX

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    for (uint32_t i = 0; i < Binding->Datapath->ProcCount; i++) {
#if defined(QUIC_PLATFORM_LINUX)
        Status =
            QuicSocketContextStartReceive(
                &Binding->SocketContexts[i],
                Datapath->ProcContexts[i].EpollFd);
#elif defined(QUIC_PLATFORM_DARWIN)
        Status =
            QuicSocketContextStartReceive(
                &Binding->SocketContexts[i],
                Datapath->ProcContexts[i].KqueueFd);
#endif // QUIC_PLATFORM_DARWIN

        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            // TODO - Clean up socket contexts
            QuicRundownRelease(&Datapath->BindingsRundown);
            QuicRundownUninitialize(&Binding->Rundown);
            QUIC_FREE(Binding);
            Binding = NULL;
        }
    }

    return Status;
#endif
}

void
QuicDataPathBindingDelete(
    _Inout_ QUIC_DATAPATH_BINDING* Binding
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingDelete(Binding);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    QuicTraceLogVerbose(
        DatapathShuttingDown,
        "[ udp][%p] Shutting down",
        Binding);

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    Binding->Shutdown = TRUE;
    for (uint32_t i = 0; i < Binding->Datapath->ProcCount; ++i) {
        QuicSocketContextUninitialize(
            &Binding->SocketContexts[i],
            &Binding->Datapath->ProcContexts[i]);
    }

    QuicRundownReleaseAndWait(&Binding->Rundown);
    QuicRundownRelease(&Binding->Datapath->BindingsRundown);

    QuicRundownUninitialize(&Binding->Rundown);
    QuicFree(Binding);
#endif
}

void
QuicDataPathBindingGetLocalAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingGetLocalAddress(Binding, Address);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
#endif
}

void
QuicDataPathBindingGetRemoteAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingGetRemoteAddress(Binding, Address);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
#endif
}

QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSetParam(
            Binding,
            Param,
            BufferLength,
            Buffer);
#else
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

QUIC_STATUS
QuicDataPathBindingGetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingGetParam(
            Binding,
            Param,
            BufferLength,
            Buffer);
#else
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const RecvContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathRecvContextToRecvPacket(RecvContext);
#else
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        (QUIC_DATAPATH_RECV_BLOCK*)
            ((char *)RecvContext - sizeof(QUIC_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
#endif
}

QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const RecvPacket
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathRecvPacketToRecvContext(RecvPacket);
#else
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QUIC_CONTAINING_RECORD(RecvPacket, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

    return (QUIC_RECV_PACKET*)(RecvBlock + 1);
#endif
}

void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    if (DatagramChain != NULL) {
        PlatDispatch->DatapathBindingReturnRecvPacket(DatagramChain);
    }
#else
    QUIC_RECV_DATAGRAM* Datagram;
    while ((Datagram = DatagramChain) != NULL) {
        DatagramChain = DatagramChain->Next;
        QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
            QUIC_CONTAINING_RECORD(Datagram, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);
        QuicPoolFree(RecvBlock->OwningPool, RecvBlock);
    }
#endif
}

QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingAllocSendContext(
            Binding,
            MaxPacketSize);
#else
    UNREFERENCED_PARAMETER(MaxPacketSize);
    QUIC_DBG_ASSERT(Binding != NULL);

#if defined(QUIC_PLATFORM_LINUX)
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext =
        &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];
#elif defined(QUIC_PLATFORM_DARWIN)
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext =
        &Binding->Datapath->ProcContexts[0];
#endif

    QUIC_DATAPATH_SEND_CONTEXT* SendContext =
        QuicPoolAlloc(&ProcContext->SendContextPool);
    if (SendContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_SEND_CONTEXT",
            0);
        goto Exit;
    }

    QuicZeroMemory(SendContext, sizeof(*SendContext));
    SendContext->Owner = ProcContext;

Exit:

    return SendContext;
#endif
}

void
QuicDataPathBindingFreeSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingFreeSendContext(SendContext);
#else
    size_t i = 0;
    for (i = 0; i < SendContext->BufferCount; ++i) {
        QuicPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    QuicPoolFree(&SendContext->Owner->SendContextPool, SendContext);
#endif
}

QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingAllocSendBuffer(
            SendContext,
            MaxBufferLength);
#else
    QUIC_BUFFER* Buffer = NULL;

    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Max batch size limit hit");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    QuicZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = QuicPoolAlloc(&SendContext->Owner->SendBufferPool);
    if (Buffer->Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Send Buffer",
            0);
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    SendContext->Iovs[SendContext->BufferCount].iov_base = Buffer->Buffer;
    SendContext->Iovs[SendContext->BufferCount].iov_len = Buffer->Length;

    ++SendContext->BufferCount;

Exit:

    return Buffer;
#endif
}

void
QuicDataPathBindingFreeSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingFreeSendBuffer(SendContext, Datagram);
#else
    QuicPoolFree(&SendContext->Owner->SendBufferPool, Datagram->Buffer);
    Datagram->Buffer == NULL;

    QUIC_DBG_ASSERT(Datagram == &SendContext->Buffers[SendContext->BufferCount - 1]);

    --SendContext->BufferCount;
#endif
}

QUIC_STATUS
QuicDataPathBindingSend(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = NULL;
    ssize_t SentByteCount = 0;
    size_t i = 0;
    socklen_t RemoteAddrLen = 0;
    QUIC_ADDR MappedRemoteAddress = { };
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;

    const size_t ControlSize = MAX(sizeof(struct in6_pktinfo), sizeof(struct in_pktinfo));
    // XXX: Compiler throws error when using default initializer, since
    // CMSG_SPACE isn't compile-time constant. I know.
    char ControlBuffer[CMSG_SPACE(ControlSize)];
    memset(ControlBuffer, 0, sizeof(ControlBuffer));

    QUIC_DBG_ASSERT(Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

#if defined(QUIC_PLATFORM_LINUX)
    SocketContext = &Binding->SocketContexts[QuicProcCurrentNumber()];
    ProcContext = &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];
#elif defined(QUIC_PLATFORM_DARWIN)
    SocketContext = &Binding->SocketContexts[0];
    ProcContext = &Binding->Datapath->ProcContexts[0];
#endif

    RemoteAddrLen =
        (AF_INET == RemoteAddress->Ip.sa_family) ?
            sizeof(RemoteAddress->Ipv4) : sizeof(RemoteAddress->Ipv6);

    if (LocalAddress == NULL) {
        QUIC_DBG_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

        for (i = SendContext->CurrentIndex;
            i < SendContext->BufferCount;
            ++i, SendContext->CurrentIndex++) {

            QuicTraceEvent(
                DatapathSendTo,
                "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!SOCKADDR!",
                Binding,
                SendContext->Buffers[i].Length,
                1,
                SendContext->Buffers[i].Length,
                LOG_ADDR_LEN(*RemoteAddress),
                (uint8_t*)RemoteAddress);

#if defined(QUIC_PLATFORM_LINUX)
            SentByteCount =
                sendto(
                    SocketContext->SocketFd,
                    SendContext->Buffers[i].Buffer,
                    SendContext->Buffers[i].Length,
                    0,
                    (struct sockaddr *)RemoteAddress,
                    RemoteAddrLen);
#elif defined(QUIC_PLATFORM_DARWIN)
            // Specifying an address on a connected-socket is an error on darwin.
            // XXX: as a server, determine if the socket is connected. I don't
            // know how to do this since this is partially for the multipath
            // code..
            SentByteCount =
                sendto(
                    SocketContext->SocketFd,
                    SendContext->Buffers[i].Buffer,
                    SendContext->Buffers[i].Length,
                    0,
                    NULL,
                    0);
#endif

            if (SentByteCount < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                    Status =
                        QuicSocketContextPendSend(
                            SocketContext,
                            SendContext,
                            ProcContext,
                            LocalAddress,
                            RemoteAddress);

                    if (QUIC_FAILED(Status)) {
                        goto Exit;
                    }

                    SendPending = TRUE;
                    goto Exit;
                } else {
                    //
                    // Completed with error.
                    //

                    Status = errno;
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[ udp][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        Status,
                        "sendto failed");
                    goto Exit;
                }
            } else {
                //
                // Completed synchronously.
                //
                QuicTraceLogVerbose(
                    DatapathSendToCompleted,
                    "[ udp][%p] sendto succeeded, bytes transferred %d",
                    SocketContext->Binding,
                    SentByteCount);
            }
        }
    } else {

        uint32_t TotalSize = 0;
        for (i = 0; i < SendContext->BufferCount; ++i) {
            SendContext->Iovs[i].iov_base = SendContext->Buffers[i].Buffer;
            SendContext->Iovs[i].iov_len = SendContext->Buffers[i].Length;
            TotalSize += SendContext->Buffers[i].Length;
        }

        QuicTraceEvent(
            DatapathSendFromTo,
            "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!SOCKADDR!, Src=%!SOCKADDR!",
            Binding,
            TotalSize,
            SendContext->BufferCount,
            SendContext->Buffers[0].Length,
            LOG_ADDR_LEN(*RemoteAddress),
            LOG_ADDR_LEN(*LocalAddress),
            (uint8_t*)RemoteAddress,
            (uint8_t*)LocalAddress);

#if defined(QUIC_PLATFORM_LINUX)
        //
        // Map V4 address to dual-stack socket format.
        //
        QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);
#endif // QUIC_PLATFORM_LINUX

        struct msghdr Mhdr = {
            .msg_name = &MappedRemoteAddress,
            .msg_namelen = sizeof(MappedRemoteAddress),
            .msg_iov = SendContext->Iovs,
            .msg_iovlen = SendContext->BufferCount,
            .msg_flags = 0
        };

        // TODO: Avoid allocating both.

        if (LocalAddress->Ip.sa_family == AF_INET) {
            Mhdr.msg_control = ControlBuffer;
            Mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

            CMsg = CMSG_FIRSTHDR(&Mhdr);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

            PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
            // TODO: Use Ipv4 instead of Ipv6.
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
        } else {
            Mhdr.msg_control = ControlBuffer;
            Mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

            CMsg = CMSG_FIRSTHDR(&Mhdr);
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

            PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
        }

        SentByteCount = sendmsg(SocketContext->SocketFd, &Mhdr, 0);

        if (SentByteCount < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                Status =
                    QuicSocketContextPendSend(
                        SocketContext,
                        SendContext,
                        ProcContext,
                        LocalAddress,
                        RemoteAddress);
                if (QUIC_FAILED(Status)) {
                    goto Exit;
                }

                SendPending = TRUE;
                goto Exit;
            } else {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "sendmsg failed");
                goto Exit;
            }
        } else {
            //
            // Completed synchronously.
            //
            QuicTraceLogVerbose(
                DatapathSendMsgCompleted,
                "[ udp][%p] sendmsg succeeded, bytes transferred %d",
                SocketContext->Binding,
                SentByteCount);
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (!SendPending) {
        QuicDataPathBindingFreeSendContext(SendContext);
    }

    return Status;
}

QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSendTo(
            Binding,
            RemoteAddress,
            SendContext);
#else
    QUIC_DBG_ASSERT(
        Binding != NULL &&
        RemoteAddress != NULL &&
        RemoteAddress->Ipv4.sin_port != 0 &&
        SendContext != NULL);

    return
        QuicDataPathBindingSend(
            Binding,
            NULL,
            RemoteAddress,
            SendContext);
#endif
}

QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSendFromTo(
            Binding,
            LocalAddress,
            RemoteAddress,
            SendContext);
#else
    QUIC_DBG_ASSERT(
        Binding != NULL &&
        LocalAddress != NULL &&
        RemoteAddress != NULL &&
        SendContext != NULL &&
        SendContext->BufferCount != 0);

    return
        QuicDataPathBindingSend(
            Binding,
            LocalAddress,
            RemoteAddress,
            SendContext);
#endif
}

uint16_t
QuicDataPathBindingGetLocalMtu(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingGetLocalMtu(Binding);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
#endif
}

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)                              \
    ({                                                              \
        long int FailureRetryResult = 0;                            \
        do {                                                        \
            FailureRetryResult = (long int)(expression);            \
        } while ((FailureRetryResult == -1L) && (errno == EINTR));  \
        FailureRetryResult;                                         \
    })
#endif

#if defined(QUIC_PLATFORM_LINUX)

void*
QuicDataPathWorkerThread(
    _In_ void* Context
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*)Context;
    QUIC_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);

    QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[ udp][%p] Worker start",
        ProcContext);

    const size_t EpollEventCtMax = 16; // TODO: Experiment.
    struct epoll_event EpollEvents[EpollEventCtMax];

    while (!ProcContext->Datapath->Shutdown) {
        int ReadyEventCount =
            TEMP_FAILURE_RETRY(
                epoll_wait(
                    ProcContext->EpollFd,
                    EpollEvents,
                    EpollEventCtMax,
                    -1));

        QUIC_FRE_ASSERT(ReadyEventCount >= 0);
        for (int i = 0; i < ReadyEventCount; i++) {
            if (EpollEvents[i].data.ptr == NULL) {
                //
                // The processor context is shutting down and the worker thread
                // needs to clean up.
                //
                QUIC_DBG_ASSERT(ProcContext->Datapath->Shutdown);
                break;
            }

            QuicSocketContextProcessEvent(
                EpollEvents[i].data.ptr,
                ProcContext,
                EpollEvents[i].events);
        }
    }

    QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[ udp][%p] Worker stop",
        ProcContext);

    return NO_ERROR;
}

#elif defined(QUIC_PLATFORM_DARWIN)

void*
QuicDataPathWorkerThread(
    _In_ void* Context
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*)Context;
    QUIC_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);
    struct kevent EventList[32];
    int Kqueue = ProcContext->KqueueFd; 

    while (TRUE) {
        int EventCount = kevent(Kqueue, NULL, 0, EventList, 32, NULL);

        if (ProcContext->Datapath->Shutdown) break;

        QUIC_DBG_ASSERT(EventCount > 0);
        
        for (int i = 0; i < EventCount; i++) {
            QuicSocketContextProcessEvent(ProcContext, &EventList[i]);
        }
    }

    return NO_ERROR;
}
#endif // QUIC_PLATFORM_DARWIN

BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingIsSendContextFull(SendContext);
#else
    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
#endif
}
