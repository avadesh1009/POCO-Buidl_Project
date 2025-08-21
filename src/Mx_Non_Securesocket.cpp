#include "Mx_Non_SecureSocket.h"
#include <Poco/Timestamp.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timespan.h>
#include <Poco/Exception.h>

using namespace Poco;
using namespace Poco::Net;

/**
 * @class CMx_NonSecureSocket
 * @brief Implements a non-secure (plain TCP) socket wrapper using POCO library.
 *
 * - Supports both client and server roles.
 * - Provides safe wrapper APIs for binding, listening, connecting, sending, receiving.
 * - Manages resources with RAII (uses std::unique_ptr for socket objects).
 * - Adds validation and error handling via custom error codes (eMxErrorCode).
 */

// ======================== Constructors & Destructor ========================

/// Constructor: allows creation in client or server mode.
/// @param isServer true = server mode, false = client mode
CMx_NonSecureSocket::CMx_NonSecureSocket() 
{
    _server = nullptr;
    _socket = nullptr;  
}

// Constructor - Initializes a non-secure socket (no ssl, no server)
CMx_NonSecureSocket::CMx_NonSecureSocket(mx_bool isServer) 
    : CMx_BaseSocket(false, isServer) // Pass "false" (no SSL) to base class
{
    _server = nullptr;
    _socket = nullptr;  
}

/// Constructor: wraps an already connected StreamSocket (e.g. accepted client).
/// @param sock The connected StreamSocket instance.
CMx_NonSecureSocket::CMx_NonSecureSocket(StreamSocket&& sock)
{
    _socket = std::make_unique<StreamSocket>(std::move(sock));
    m_bIsConnected = true;
}

/// Destructor: ensures sockets are closed and resources released.
CMx_NonSecureSocket::~CMx_NonSecureSocket() 
{ 
    close(); 
}

// ============================== Server APIs ==============================

/**
 * @brief Bind socket to port and IP mode (IPv4 / IPv6 / Dual-stack).
 * 
 * @param port          Port number (1–65535).
 * @param ipMode        IP binding mode (IPv4, IPv6, DualStack).
 * @param reuseAddress  Allow address reuse.
 * @param reusePort     Allow port reuse (mainly for IPv6).
 * 
 * @return eMxErrorCode indicating success/failure.
 */
eMxErrorCode CMx_NonSecureSocket::bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress , mx_bool reusePort ,eSslVerificationMode verifyMode)
{
    // Preconditions: must be server, non-SSL
    if (m_bIsSSL) 
    {
        LOG_ERR("[Bind] Failed: API not allowed in SSL mode.");
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (!m_bIsServer) 
    {
        LOG_ERR("[Bind] Failed: API can only be used in server mode.");
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    // Validate port number
    if (port == 0 || port > MX_SOCKET_PORT_MAX) 
    {
        LOG_ERR("[Bind] Failed: Invalid port number (" << port << ")");
        return eMxErrorCode::ERR_INVALID_PORT;
    }

    // Try to allocate server socket
    try 
    {
        _server = std::make_unique<ServerSocket>();
    }
    catch (const std::bad_alloc&) 
    {
        LOG_ERR("[Bind] Failed: Memory allocation for ServerSocket.");
        return eMxErrorCode::OUT_OF_MEMORY;
    }
    catch (...) 
    {
        LOG_ERR("[Bind] Failed: Unknown error while creating ServerSocket.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Helper: Bind IPv4
    auto bindIPv4 = [&]() -> eMxErrorCode {
        try {
            SocketAddress addr(IPAddress::IPv4, static_cast<Poco::UInt16>(port));
            _server->bind(addr, reuseAddress);
            auto boundAddr = _server->address(); // actual IP:port
            LOG_INFO("[Bind] Success: Bound on IPv4 -> " 
                     << boundAddr.host().toString() << ":" << boundAddr.port());
            return eMxErrorCode::NO_ERR;
        }
        catch (const Poco::Exception& ex) {
            LOG_ERR("[Bind] IPv4 bind failed on port " << port 
                    << " | Error: " << ex.displayText());
            return eMxErrorCode::ERR_SERVICE_START_FAILED;
        }
    };

    // Helper: Bind IPv6 / DualStack
    auto bindIPv6 = [&](bool dualStack) -> eMxErrorCode {
        try {
            SocketAddress addr(IPAddress::IPv6, static_cast<Poco::UInt16>(port));
            _server->bind6(addr, reuseAddress, reusePort, !dualStack); // !dualStack = IPv6-only
            auto boundAddr = _server->address(); // actual IP:port
            if (dualStack)
                LOG_INFO("[Bind] Success: Bound DualStack (IPv6+IPv4) -> " 
                         << boundAddr.host().toString() << ":" << boundAddr.port());
            else
                LOG_INFO("[Bind] Success: Bound IPv6 -> " 
                         << boundAddr.host().toString() << ":" << boundAddr.port());
            return eMxErrorCode::NO_ERR;
        }
        catch (const NotImplementedException&) {
            LOG_ERR("IPv6 not supported on this system.");
            return eMxErrorCode::ERR_IPV6_NOT_SUPPORT;
        }
        catch (const Poco::Exception& ex) {
            LOG_ERR("[Bind] IPv6 bind failed on port " << port 
                    << " | Error: " << ex.displayText());
            return eMxErrorCode::ERR_SERVICE_START_FAILED;
        }
    };

    // Select binding strategy
    switch (ipMode) 
    {
        case eIpBindingMode::DualStack: return bindIPv6(true);
        case eIpBindingMode::IPv6:      return bindIPv6(false);
        case eIpBindingMode::IPv4:      return bindIPv4();
        default:
            LOG_ERR("[Bind] Failed: Unsupported IP binding mode (" << (int)ipMode << ")");
            return eMxErrorCode::UNKNOWN_ERROR;
    }

}

/**
 * @brief Start listening for incoming connections.
 * @param backlog Maximum pending connection queue length.
 */
eMxErrorCode CMx_NonSecureSocket::listen(mx_uint64 backlog)
{
    // --- Validation ---
    if (m_bIsSSL) 
    {
        LOG_ERR("[Listen] Failed: not supported for SSL socket in NonSecureSocket class.");
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (!m_bIsServer)
    {
        LOG_ERR("[Listen] Failed: called in client mode (server mode required).");
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (!_server) 
    {
        LOG_ERR("[Listen] Failed: server socket not initialized. Call bind() first.");
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (backlog == 0)
    {
        LOG_WARN("[Listen] Invalid backlog (0). Using default backlog = " 
                 << MX_DEFAULT_BACKLOG);
        backlog = MX_DEFAULT_BACKLOG;
    }

    try 
    {
        _server->listen(static_cast<mx_uint64>(backlog));

        auto boundAddr = _server->address(); // actual bound IP/port
        LOG_INFO("[Listen] Success: Server listening on " 
                 << boundAddr.host().toString() << ":" << boundAddr.port()
                 << " (backlog = " << backlog << ")");

        return eMxErrorCode::NO_ERR;
    }
    catch (const Poco::Exception& ex) 
    {
        LOG_ERR("[Listen] Failed: Poco exception: " << ex.displayText());
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }
    catch (...) 
    {
        LOG_ERR("[Listen] Failed: Unknown exception.");
        return eMxErrorCode::UNKNOWN_ERROR;
        
    }
}

/**
 * @brief Accept an incoming client connection.
 * @return Pointer to CMx_BaseSocket (wrapped client connection).
 */
std::unique_ptr<CMx_BaseSocket> CMx_NonSecureSocket::accept() 
{

    // --- Validation ---
    if (m_bIsSSL) 
    {
        LOG_ERR("[Accept] Failed: not supported for SSL socket in NonSecureSocket class.");
        return nullptr;
    }

    if (!m_bIsServer)
    {
        LOG_ERR("[Accept] Failed: called in client mode (server mode required).");
        return nullptr;
    }

    if (!_server) 
    {
        LOG_ERR("[Accept] Failed: server socket not initialized. Call bind() and listen() first.");
        return nullptr;
    }

    try 
    {

        // Accept client connection
        SocketAddress clientAddr;
        StreamSocket client = _server->acceptConnection(clientAddr);

        if (!client.impl()) 
        {
            LOG_ERR("[Accept] Failed: returned an invalid client socket.");
            return nullptr;
        }

        LOG_INFO("[Accept] Success: Client connected from " << clientAddr.toString());

        auto newClient = std::make_unique<CMx_NonSecureSocket>(std::move(client));
        newClient->m_bIsConnected = true;
        newClient->m_bIsServer = false;

        return newClient;
    }
    catch (const Poco::TimeoutException& ex) 
    {
        LOG_WARN("[Accept] Timed out: " << ex.displayText());
        return nullptr;
    }
    catch (const Poco::IOException& ex) 
    {
        LOG_ERR("[Accept] I/O error: " << ex.displayText());
        return nullptr;
    }
    catch (const Poco::Exception& ex) 
    {
        LOG_ERR("[Accept] Failed: Poco exception: " << ex.displayText());
        return nullptr;
    }
    catch (...) 
    {
        LOG_ERR("[Accept] Failed: Unknown exception.");
        return nullptr;

    }
}

// ============================== Client APIs ==============================

/**
 * @brief Connect to remote server.
 * @param ip             Remote server IP (string).
 * @param port           Remote port (1–65535).
 * @param timeoutSeconds Timeout in seconds.
 */
eMxErrorCode CMx_NonSecureSocket::connect(const std::string& ip, mx_uint64 port, mx_uint64 timeoutSeconds,eSslVerificationMode verifyMode) 
{
    // --- Validation for Non-Secure Client ---
    if (m_bIsSSL) 
    {
        LOG_ERR("[Connect] Failed: Non-secure socket cannot use SSL mode.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    if (m_bIsServer) 
    {
        LOG_ERR("[Connect] Failed: Cannot call connect() on a server socket.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    if (m_bIsConnected) 
    {
        LOG_ERR("[Connect] Failed: Socket already connected to a server.");
        return eMxErrorCode::ERR_SOCKET_ALREADY_CONNECTED;
    }

     // --- Validation ---
    if (ip.empty()) 
    {
        LOG_ERR("[Connect] Failed: Empty IP address.");
        return eMxErrorCode::ERR_INVALID_IP_RANGE;
    }

    if (port == 0 || port > MX_SOCKET_PORT_MAX) 
    {
        LOG_ERR("[Connect] Failed: Invalid port (" << port << ")");
        return eMxErrorCode::ERR_INVALID_PORT;
    }

    try 
    {
        if (!_socket) 
        {
            try 
            {
                _socket = std::make_unique<StreamSocket>();
            }
            catch (const std::bad_alloc&) 
            {
                LOG_ERR("[Connect] Failed: Memory allocation for StreamSocket.");
                return eMxErrorCode::OUT_OF_MEMORY;
            }
        }

        SocketAddress address(ip, static_cast<Poco::UInt16>(port));
        Poco::Timespan timeout(static_cast<long>(timeoutSeconds), 0);

        _socket->connect(address, timeout);

        LOG_INFO("[Connect] Success: Connected to " << address.toString()
                 << " (timeout = " << timeoutSeconds << "s)");

        m_bIsConnected = true;
        m_bIsServer = false;

        return eMxErrorCode::NO_ERR;
    }
    catch (const Poco::TimeoutException& ex) 
    {
        LOG_ERR("[Connect] Timed out while connecting to " << ip << ":" << port
                << " | Error: " << ex.displayText());
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (const Poco::Exception& ex) {
        LOG_ERR("[Connect] Failed while connecting to " << ip << ":" << port
                << " | Poco exception: " << ex.displayText());
        return eMxErrorCode::ERR_CONNECTION_FAILED;
    }
    catch (...) {
        LOG_ERR("[Connect] Failed: Unknown exception while connecting to "
                << ip << ":" << port);
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// ============================== Data Transfer APIs ==============================

/**
 * @brief Send raw buffer data.
 */
eMxErrorCode CMx_NonSecureSocket::send(const mx_char* buffer, mx_uint64 len) 
{
    if (!_socket) 
    {
        LOG_ERR("[Send] Failed: Socket not initialized.");
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    if (!isConnected()) 
    {
        LOG_ERR("[Send] Failed: Socket is not connected.");
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

    if(buffer == nullptr || len == 0)
    {
        LOG_ERR("[Send] Failed: Invalid buffer (ptr=" << static_cast<const void*>(buffer) 
                << ", len=" << len << ")");
        
        return eMxErrorCode::ERR_INVALID_BUFFER;
    }

    if (!isWritable(MX_SOCKET_READY_TIMEOUT_MS))
    {
        LOG_ERR("[Send] Failed: Socket not ready for writing (timeout=" 
                << MX_SOCKET_READY_TIMEOUT_MS << "ms).");

        return eMxErrorCode::ERR_SOCKET_NOT_READY_WRITE;
    }
        

    try 
    {
        int sendBufSize = _socket->getSendBufferSize();
        const mx_char* dataPtr = static_cast<const mx_char*>(buffer);
        size_t totalSent = 0;

        while (totalSent < len) 
        {
            // Calculate how much we can send in this chunk
            int chunkSize = static_cast<int>(
                std::min(static_cast<mx_uint64>(len - totalSent), static_cast<mx_uint64>(sendBufSize))
            );

            int n = _socket->sendBytes(dataPtr + totalSent, chunkSize);

            if (n <= 0) {
                LOG_WARN("[Send] Failed: sendBytes() returned " << n 
                         << ". Socket may be closed.");
                m_bIsConnected = false;
                return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }

            totalSent += n;
        }

        return eMxErrorCode::NO_ERR;
    } 
    catch (const Poco::TimeoutException& ex) 
    {
        LOG_ERR("[Send] Timeout while sending data: " << ex.displayText());
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    } 
    catch (const Poco::Exception& ex) 
    {
        LOG_ERR("[Send] Failed: Poco exception during send: " << ex.displayText());
        return eMxErrorCode::ERR_CONNECTION_FAILED;
    } 
    catch (...) 
    {
        LOG_ERR("[Send] Failed: Unknown exception.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/**
 * @brief Send message as string.
 */
eMxErrorCode CMx_NonSecureSocket::sendMessage(const std::string& msg) 
{
    if (msg.empty()) 
    {
        LOG_ERR("sendMessage() called with empty message.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Now send the actual message
    eMxErrorCode errcode = send(reinterpret_cast<const mx_char*>(msg.data()), static_cast<int>(msg.size()));
    if (errcode != eMxErrorCode::NO_ERR) 
    {
        LOG_ERR("Failed to send message body.");
        return errcode;
    }

    return eMxErrorCode::NO_ERR; // success
}

/**
 * @brief Receive raw data into buffer.
 */
eMxErrorCode CMx_NonSecureSocket::receive(mx_char* buffer, mx_uint64 maxLen) 
{

    if (!_socket || maxLen == 0)
    {
        LOG_ERR("receive() failed: socket not initialized or invalid maxLen=" << maxLen);
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    if (!isConnected()) 
    {
        LOG_ERR("receive() failed: socket is not connected.");
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

    // First check if socket is readable
    if (!isReadable(MX_SOCKET_READY_TIMEOUT_MS)) 
    {
        LOG_WARN("receive() failed: socket not ready for read within timeout(" 
                 << MX_SOCKET_READY_TIMEOUT_MS << " ms).");
        return eMxErrorCode::ERR_SOCKET_NOT_READY_READ;  // no data within timeout
    }
    
    try 
    {

        int recvBufSize = _socket->getReceiveBufferSize();
        if (recvBufSize <= 0)
        {
            LOG_WARN("System returned recvBufSize=0, using fallback=" << MX_MAX_RECEIVE_CHUNK);
            recvBufSize = MX_MAX_RECEIVE_CHUNK; // default fallback if system returns 0
        }


        mx_uint64 totalReceived = 0;

        while (totalReceived < maxLen) 
        {
            // Calculate how much to read in this iteration
            mx_uint64 chunkSize = std::min(static_cast<mx_uint64>(recvBufSize), static_cast<mx_uint64>(maxLen - totalReceived));

            int n = _socket->receiveBytes(buffer + totalReceived, static_cast<int>(chunkSize));

            if (n == 0) 
            {
                LOG_INFO("Connection closed gracefully by peer. totalReceived=" << totalReceived);
                return (totalReceived > 0) ? eMxErrorCode::NO_ERR : eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }

            totalReceived += n;

            // If less than requested chunk was read, stop (no more data currently available)
            if (n < static_cast<int>(chunkSize))
                break;
        
        }

        return (totalReceived > 0) ? eMxErrorCode::NO_ERR : eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (const Poco::TimeoutException& ex) 
    {
        LOG_ERR("Receive timeout: " << ex.displayText());
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (const Poco::Exception& ex) 
    {
        LOG_ERR("General POCO exception in receive: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (...) 
    {
        LOG_ERR("Unknown exception in receive().");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/**
 * @brief Receive until EOM (end-of-message) character.
 */
eMxErrorCode CMx_NonSecureSocket::receiveUntilEOM(std::string& msg)
{
    if (!_socket)
    {
        LOG_ERR("receiveUntilEOM failed: socket not initialized.");
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    if (!isConnected()) 
    {
        LOG_ERR("receiveUntilEOM failed: socket is not connected.");
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
    }

    try
    {
        msg.clear();

        while (true)
        {
            std::string readbuffer(MX_BUFFER_SIZE, '\0'); // allocate buffer
            int received = _socket->receiveBytes(&readbuffer[0], MX_BUFFER_SIZE);
            
            if (received > 0)
            {
                // append only valid part
                msg.append(readbuffer.data(), received);

                // search only in accumulated msg
                size_t pos = msg.find(EOM);
                if (pos != std::string::npos)
                {
                    // trim msg up to EOM (inclusive)
                    msg.resize(pos + 1);

                    LOG_INFO("receiveUntilEOM: Successfully received complete message (length = " 
                             << msg.size() << ")");
                    return eMxErrorCode::NO_ERR;
                }
            }
            else
            {
                LOG_ERR("receiveUntilEOM: socket disconnected while receiving.");
                return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }
        }
    }
    catch (const Poco::Exception& ex)
    {
        LOG_ERR("receiveUntilEOM Poco::Exception: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (const std::exception& ex)
    {
        LOG_ERR("receiveUntilEOM std::exception: " << ex.what());
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (...)
    {
        LOG_ERR("receiveUntilEOM Unknown exception.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// ============================== Utility APIs ==============================

/// Check if socket is readable within timeout
mx_bool CMx_NonSecureSocket::isReadable(mx_uint64 timeoutMs) 
{
    if (!_socket || !isConnected()) return false;

    try
    {
        Poco::Timespan t(timeoutMs * 1000);
        return _socket->poll(t, Poco::Net::Socket::SELECT_READ);
    }
    catch (...)
    {
        return false;
    }
}

/// Check if socket is writable within timeout
mx_bool CMx_NonSecureSocket::isWritable(mx_uint64 timeoutMs) 
{
    if (!_socket || !isConnected()) return false;

    try
    {
        Poco::Timespan t(timeoutMs * 1000);
        return _socket->poll(t, Poco::Net::Socket::SELECT_WRITE);
    }
    catch (...)
    {
        return false;
    }
}

/// Enable/disable blocking mode
eMxErrorCode CMx_NonSecureSocket::setBlocking(mx_bool blocking) 
{
    try 
    {

        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

        _socket->setBlocking(blocking);
        m_bIsBlocking = blocking;

        return eMxErrorCode::NO_ERR;

    } catch (...) 
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/// Set receive timeout
eMxErrorCode CMx_NonSecureSocket::setReceiveTimeout(mx_uint64 receivetimeoutMs)
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
        
        _socket->setReceiveTimeout(Poco::Timespan(receivetimeoutMs * 1000));

        return eMxErrorCode::NO_ERR;

    } catch (const Poco::Exception& ex) 
    {
        LOG_ERR("setReceiveTimeout failed: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/// Set send timeout
eMxErrorCode CMx_NonSecureSocket::setSendTimeout(mx_uint64 sendtimeoutMs) 
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

        _socket->setSendTimeout(Poco::Timespan(sendtimeoutMs * 1000));

        return eMxErrorCode::NO_ERR;

    } catch (const Poco::Exception& ex) 
    {
        LOG_ERR("setSendTimeout failed: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    } catch (...) 
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/// Set receive buffer size
eMxErrorCode CMx_NonSecureSocket::setReceiveBufferSize(mx_uint64 size) 
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

        _socket->setReceiveBufferSize(size);

        return eMxErrorCode::NO_ERR;

    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/// Set send buffer size
eMxErrorCode CMx_NonSecureSocket::setSendBufferSize(mx_uint64 size) 
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    
        _socket->setSendBufferSize(size);
        return eMxErrorCode::NO_ERR;

    } catch (...) 
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/**
 * @brief Close socket and free resources.
 */
eMxErrorCode CMx_NonSecureSocket::close() 
{
    try 
    {
        std::string peer = getPeerAddress(); // try get client info

        if (_socket && _socket->impl()->initialized())
        {
            try {
                _socket->shutdown();
                LOG_INFO("Socket shutdown successful for peer: " << peer);
            } catch (const Poco::Exception& ex) {
                LOG_ERR("Socket shutdown failed for peer: " << peer 
                        << " | Poco::Exception: " << ex.displayText());
            }

            try {
                _socket->close();
                LOG_INFO("Socket close successful for peer: " << peer);
            } catch (const Poco::Exception& ex) {
                LOG_ERR("Socket close failed for peer: " << peer 
                        << " | Poco::Exception: " << ex.displayText());
            }

            _socket.reset();
        }

        if (_server) 
        {
            try {
                _server->close();
                LOG_INFO("Server socket closed successfully.");
            } catch (const Poco::Exception& ex) {
                LOG_ERR("Server close failed | Poco::Exception: " << ex.displayText());
            }
            _server.reset();
        }

        m_bIsConnected = false;
        m_bIsServer = false;

        LOG_INFO("Socket resources released successfully. Peer: " << peer);

        return eMxErrorCode::NO_ERR;

    } 
    catch (const std::exception& ex) 
    {
        LOG_ERR("close() std::exception: " << ex.what());
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (...) 
    {
        LOG_ERR("close() Unknown exception occurred.");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// temp: expose peer address mainly for debugging/logging
std::string CMx_NonSecureSocket::getPeerAddress() {
    return _socket->peerAddress().toString();
}
