#include "Mx_Non_SecureSocket.h"
#include <Poco/Timestamp.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timespan.h>
#include <Poco/Exception.h>
#include <iostream>

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
eMxErrorCode CMx_NonSecureSocket::bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress , mx_bool reusePort )
{
    // Preconditions: must be server, non-SSL
    if (m_bIsSSL) 
    {
        std::cerr << "[Error] Bind API is not allowed in SSL mode." << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (!m_bIsServer) 
    {
        std::cerr << "[Error] Bind API can only be used in server mode." << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    // Validate port number
    if (port == 0 || port > MX_SOCKET_PORT_MAX) 
    {
        std::cerr << "[Error] Invalid port number: " << port << std::endl;
        return eMxErrorCode::ERR_INVALID_PORT;
    }

    // Try to allocate server socket
    try 
    {
        _server = std::make_unique<ServerSocket>();
    }
    catch (const std::bad_alloc&) 
    {
        std::cerr << "[Error] Memory allocation failed for ServerSocket." << std::endl;
        return eMxErrorCode::OUT_OF_MEMORY;
    }
    catch (...) 
    {
        std::cerr << "[Error] Unknown error while creating ServerSocket." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Helper: Bind IPv4
    auto bindIPv4 = [&]() -> eMxErrorCode {
        try {
            SocketAddress addr(IPAddress::IPv4, static_cast<Poco::UInt16>(port));
            _server->bind(addr, reuseAddress);
            std::cout << "[Info] Bound using IPv4 only" << std::endl;
            return eMxErrorCode::NO_ERR;
        }
        catch (const Poco::Exception& ex) {
            std::cerr << "[Error] IPv4 bind failed: " << ex.displayText() << std::endl;
            return eMxErrorCode::ERR_SERVICE_START_FAILED;
        }
    };

    // Helper: Bind IPv6 / DualStack
    auto bindIPv6 = [&](bool dualStack) -> eMxErrorCode {
        try {
            SocketAddress addr(IPAddress::IPv6, static_cast<Poco::UInt16>(port));
            _server->bind6(addr, reuseAddress, reusePort, !dualStack); // !dualStack = IPv6-only
            std::cout << (dualStack ? "[Info] Bound using dual-stack (IPv6+IPv4)"
                                    : "[Info] Bound using IPv6 only") << std::endl;
            return eMxErrorCode::NO_ERR;
        }
        catch (const NotImplementedException&) {
            std::cerr << "[Error] IPv6 not supported on this system." << std::endl;
            return eMxErrorCode::ERR_IPV6_NOT_SUPPORT;
        }
        catch (const Poco::Exception& ex) {
            std::cerr << "[Error] IPv6 bind failed: " << ex.displayText() << std::endl;
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
            std::cerr << "[Error] Unsupported IP binding mode." << std::endl;
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
        std::cerr << "[Error] listen() not supported for SSL socket in NonSecureSocket class." << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (!m_bIsServer)
    {
        std::cerr << "[Error] listen() called but socket was not bound in server mode." << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (!_server) 
    {
        std::cerr << "[Error] listen() called but server socket is not initialized." << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (backlog == 0)
    {
        std::cerr << "[Warning] Invalid backlog (0). Using default backlog = MX_DEFAULT_BACKLOG." << std::endl;
        backlog = MX_DEFAULT_BACKLOG;
    }

    try 
    {
        _server->listen(static_cast<mx_uint64>(backlog));

        std::cout << "[Info] Server is now listening (backlog = " << backlog << ")" << std::endl;
        return eMxErrorCode::NO_ERR;
    }
    catch (const Poco::Exception& ex) 
    {
        std::cerr << "[Error] Failed to start listening: " << ex.displayText() << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }
    catch (...) 
    {
        std::cerr << "[Error] Unknown exception in listen()." << std::endl;
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
        std::cerr << "[Error] listen() not supported for SSL socket in NonSecureSocket class." << std::endl;
        return nullptr;
    }

    if (!m_bIsServer)
    {
        std::cerr << "[Error] listen() called but socket was not bound in server mode." << std::endl;
        return nullptr;
    }

    if (!_server) 
    {
        std::cerr << "[Error] accept() called but server socket is not initialized." << std::endl;
        return nullptr;
    }

    try 
    {

        // Accept client connection
        SocketAddress clientAddr;
        StreamSocket client = _server->acceptConnection(clientAddr);

        if (!client.impl()) 
        {
            std::cerr << "[Error] accept() returned an invalid client socket." << std::endl;
            return nullptr;
        }

        std::cout << "[Info] Client connected from " << clientAddr.toString() << std::endl;

        // Wrap the StreamSocket into a new CMx_NonSecureSocket
        
        auto newClient = std::make_unique<CMx_NonSecureSocket>(std::move(client));
        
        newClient->m_bIsConnected = true;
        newClient->m_bIsServer = false;

        return newClient;
    }
    catch (const Poco::TimeoutException& ex) 
    {
        std::cerr << "[Warning] Accept timed out: " << ex.displayText() << std::endl;
        return nullptr;
    }
    catch (const Poco::IOException& ex) 
    {
        std::cerr << "[Error] I/O error during accept: " << ex.displayText() << std::endl;
        return nullptr;
    }
    catch (const Poco::Exception& ex) 
    {
        std::cerr << "[Error] Accept failed: " << ex.displayText() << std::endl;
        return nullptr;
    }
    catch (...) 
    {
        std::cerr << "[Error] Unknown exception in accept()." << std::endl;
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
eMxErrorCode CMx_NonSecureSocket::connect(const std::string& ip, mx_uint64 port, mx_uint64 timeoutSeconds) 
{
    // --- Validation for Non-Secure Client ---
    if (m_bIsSSL) 
    {
        std::cerr << "[Error] Non-secure socket cannot use SSL mode." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    if (m_bIsServer) 
    {
        std::cerr << "[Error] Cannot call connect() on a server socket." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    if (m_bIsConnected) 
    {
        std::cerr << "[Error] Socket is already connected to a server." << std::endl;
        return eMxErrorCode::ERR_SOCKET_ALREADY_CONNECTED;
    }

     // --- Validation ---
    if (ip.empty()) 
    {
        std::cerr << "[Error] connect() called with empty IP address." << std::endl;
        return eMxErrorCode::ERR_INVALID_IP_RANGE;
    }

    if (port == 0 || port > MX_SOCKET_PORT_MAX) 
    {
        std::cerr << "[Error] connect() called with invalid port: " << port << std::endl;
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
                std::cerr << "[Error] Memory allocation failed while creating StreamSocket." << std::endl;
                return eMxErrorCode::OUT_OF_MEMORY;
            }
        }

        SocketAddress address(ip, static_cast<Poco::UInt16>(port));
        Poco::Timespan timeout(static_cast<long>(timeoutSeconds), 0);

        _socket->connect(address, timeout);

        std::cout << "[Info] Connected to " << address.toString()
                  << " (timeout = " << timeoutSeconds << "s)" << std::endl;

        m_bIsConnected = true;
        m_bIsServer = false;

        return eMxErrorCode::NO_ERR;
    }
    catch (const Poco::TimeoutException& ex) 
    {
        std::cerr << "[Error] Connection timed out: " << ex.displayText() << std::endl;
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (const Poco::Exception& ex) {
        std::cerr << "[Error] General POCO exception during connect: " << ex.displayText() << std::endl;
        return eMxErrorCode::ERR_CONNECTION_FAILED;
    }
    catch (...) {
        std::cerr << "[Error] Unknown exception in connect()." << std::endl;
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
        std::cerr << "[Error] Socket not initialized." << std::endl;
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    if (!isConnected()) 
    {
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

    if(buffer == nullptr || len == 0)
        return eMxErrorCode::ERR_INVALID_BUFFER;

    if (!isWritable(MX_SOCKET_READY_TIMEOUT_MS))
        return eMxErrorCode::ERR_SOCKET_NOT_READY_WRITE;

    try 
    {
        int sendBufSize = _socket->getSendBufferSize();
        const mx_char* dataPtr = static_cast<const mx_char*>(buffer);
        size_t totalSent = 0;

        while (totalSent < len) 
        {
            // Calculate how much we can send in this chunk
            int chunkSize = static_cast<int>(
                std::min(len - totalSent, static_cast<size_t>(sendBufSize))
            );

            int n = _socket->sendBytes(dataPtr + totalSent, chunkSize);

            if (n <= 0) {
                std::cerr << "[Warning] Send failed or socket closed (sent=" 
                          << n << ")." << std::endl;
                m_bIsConnected = false;
                return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }

            totalSent += n;
        }

        return eMxErrorCode::NO_ERR;
    } 
    catch (const Poco::TimeoutException& ex) {
        std::cerr << "[Error] Send timeout: " << ex.displayText() << std::endl;
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    } 
    catch (...) {
        std::cerr << "[Error] Unknown exception in send()." << std::endl;
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
        std::cerr << "[Error] sendMessage() called with empty message." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Now send the actual message
    eMxErrorCode errcode = send(reinterpret_cast<const mx_char*>(msg.data()), static_cast<int>(msg.size()));
    if (errcode != eMxErrorCode::NO_ERR) 
    {
        std::cerr << "[Error] Failed to send message body." << std::endl;
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
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;


    if (!isConnected()) 
    {
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

    // First check if socket is readable
    if (!isReadable(MX_SOCKET_READY_TIMEOUT_MS)) 
    {
        return eMxErrorCode::ERR_SOCKET_NOT_READY_READ;  // no data within timeout
    }
    
    try 
    {

        int recvBufSize = _socket->getReceiveBufferSize();
        if (recvBufSize <= 0)
            recvBufSize = MX_MAX_RECEIVE_CHUNK; // default fallback if system returns 0
    
        mx_uint64 totalReceived = 0;

        while (totalReceived < maxLen) 
        {
            // Calculate how much to read in this iteration
            mx_uint64 chunkSize = std::min<mx_uint64>(recvBufSize, maxLen - totalReceived);

            int n = _socket->receiveBytes(buffer + totalReceived, static_cast<int>(chunkSize));

            if (n == 0) 
            {
                std::cerr << "[Info] Connection closed gracefully by peer." << std::endl;
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
        std::cerr << "[Error] Receive timeout: " << ex.displayText() << std::endl;
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (const Poco::Exception& ex) 
    {
        std::cerr << "[Error] General POCO exception in receive: " << ex.displayText() << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (...) 
    {
        std::cerr << "[Error] Unknown exception in receive()." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/**
 * @brief Receive until EOM (end-of-message) character.
 */
eMxErrorCode CMx_NonSecureSocket::receiveUntilEOM(std::string& msg)
{
    // --- Preconditions ---
    if (!_socket)
    {
        std::cerr << "[Error] receiveUntilEOM() called but socket is not initialized.\n";
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    if (!isConnected()) 
    {
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

    msg.clear();

    try
    {
        char ch;
        while (true)
        {
            int n = 0;

            try
            {
                n = _socket->receiveBytes(&ch, 1); // read 1 byte
            }
            catch (const Poco::TimeoutException& ex)
            {
                std::cerr << "[Warning] Socket read timed out: " << ex.displayText() << "\n";
                return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
            }
            catch (...)
            {
                std::cerr << "[Error] Unknown exception in receiveUntilEOM().\n";
                return eMxErrorCode::UNKNOWN_ERROR;
            }

            if (n <= 0)
            {
                std::cerr << "[Info] Socket disconnected by peer.\n";
                return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  
            }

            msg += ch;

            // check EOM
            if (ch == EOM)
                break;
        }

        return eMxErrorCode::NO_ERR;
    }
    catch (...)
    {
        std::cerr << "[Error] Unknown exception in receiveUntilEOM.\n";
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
        std::cerr << "[Error] setReceiveTimeout failed: " << ex.displayText() << std::endl;
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
        std::cerr << "[Error] setSendTimeout failed: " << ex.displayText() << std::endl;
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
        if (_socket && _socket->impl()->initialized())
        {
            _socket->shutdown();
            _socket->close();
            _socket.reset();
        }

        if (_server) 
        {
            _server->close();
            _server.reset();
        }

        m_bIsConnected = false;
        m_bIsServer = false;

        return eMxErrorCode::NO_ERR;

    } catch (...) 
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

}

std::string CMx_NonSecureSocket::getPeerAddress() {
    return _socket->peerAddress().toString();
}
