#include "Mx_Non_SecureSocket.h"
#include <Poco/Timestamp.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timespan.h>
#include <Poco/Exception.h>
#include <iostream>

using namespace Poco;
using namespace Poco::Net;

// Constructor - Initializes a non-secure socket (no server, no client)
CMx_NonSecureSocket::CMx_NonSecureSocket() : CMx_BaseSocket(false, false) 
{
    m_server = nullptr;
    m_sock = nullptr;  
}

// Constructor - Wraps an already accepted/connected socket
CMx_NonSecureSocket::CMx_NonSecureSocket(StreamSocket&& sock) : CMx_BaseSocket(false, false)
{
    m_sock = std::make_unique<StreamSocket>(std::move(sock));
    m_bIsConnected = true;
}

// Destructor - ensures socket is closed properly
CMx_NonSecureSocket::~CMx_NonSecureSocket() 
{ 
    close(); 
}

// Bind socket to given port & IP mode (IPv4/IPv6/Dual-stack)
eMxErrorCode CMx_NonSecureSocket::bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress , mx_bool reusePort )
{
    // --- Preconditions ---
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

    // --- Input Validations ---
    if (port == 0 || port > 65535) 
    {
        std::cerr << "[Error] Invalid port number: " << port << std::endl;
        return eMxErrorCode::ERR_INVALID_PORT;
    }

    if (m_server) 
    {
        std::cerr << "[Error] Server socket already exists. Resetting..." << std::endl;
        m_server.reset(); // cleanup old socket
    }

    try 
    {
        m_server = std::make_unique<ServerSocket>();
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

    auto bindIPv4 = [&]() -> eMxErrorCode {
        try {
            SocketAddress addr(IPAddress::IPv4, static_cast<Poco::UInt16>(port));
            m_server->bind(addr, reuseAddress);
            std::cout << "[Info] Bound using IPv4 only" << std::endl;
            return eMxErrorCode::NO_ERR;
        }
        catch (const Poco::Exception& ex) {
            std::cerr << "[Error] IPv4 bind failed: " << ex.displayText() << std::endl;
            return eMxErrorCode::ERR_SERVICE_START_FAILED;
        }
    };

    auto bindIPv6 = [&](bool dualStack) -> eMxErrorCode {
        try {
            SocketAddress addr(IPAddress::IPv6, static_cast<Poco::UInt16>(port));
            m_server->bind6(addr, reuseAddress, reusePort, !dualStack); // !dualStack = IPv6-only
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

    // --- Binding Logic ---
    eMxErrorCode result = eMxErrorCode::NO_ERR;
    switch (ipMode) 
    {
        case eIpBindingMode::DualStack:
            result = bindIPv6(true);
            break;

        case eIpBindingMode::IPv6:
            result = bindIPv6(false);
            break;

        case eIpBindingMode::IPv4:
            result = bindIPv4();
            break;

        default:
            std::cerr << "[Error] Unsupported IP binding mode." << std::endl;
            result = eMxErrorCode::UNKNOWN_ERROR;
            break;
    }

    return result;
}

// Start listening for incoming connections with backlog
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

    if (!m_server) 
    {
        std::cerr << "[Error] listen() called but server socket is not initialized." << std::endl;
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    if (backlog == 0)
    {
        std::cerr << "[Warning] Invalid backlog (0). Using default backlog = SOMAXCONN." << std::endl;
        backlog = MX_DEFAULT_BACKLOG;
    }

    try 
    {
        m_server->listen(static_cast<int>(backlog));
        m_bIsServer = true;

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

// Accept incoming client connection and wrap into CMx_NonSecureSocket
std::unique_ptr<CMx_BaseSocket> CMx_NonSecureSocket::accept() 
{

    // --- Validation ---
    if (!m_server) 
    {
        std::cerr << "[Error] accept() called but server socket is not initialized." << std::endl;
        return nullptr;
    }

    try 
    {

        // Accept client connection
        SocketAddress clientAddr;
        StreamSocket client = m_server->acceptConnection(clientAddr);

        if (!client.impl()) 
        {
            std::cerr << "[Error] accept() returned an invalid client socket." << std::endl;
            return nullptr;
        }

        std::cout << "[Info] Client connected from " << clientAddr.toString() << std::endl;

        // Wrap the StreamSocket into a new CMx_NonSecureSocket
        auto newClient = std::make_unique<CMx_NonSecureSocket>();
        try 
        {
            newClient->m_sock = std::make_unique<StreamSocket>(std::move(client));
        }
        catch (const std::bad_alloc&)
        {
            std::cerr << "[Error] Memory allocation failed while creating client socket wrapper." << std::endl;
            return nullptr;
        }

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

// Connect to a remote server with timeout
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
        return eMxErrorCode::UNKNOWN_ERROR;
    }

     // --- Validation ---
    if (ip.empty()) 
    {
        std::cerr << "[Error] connect() called with empty IP address." << std::endl;
        return eMxErrorCode::ERR_INVALID_IP_RANGE;
    }

    if (port == 0 || port > 65535) 
    {
        std::cerr << "[Error] connect() called with invalid port: " << port << std::endl;
        return eMxErrorCode::ERR_INVALID_PORT;
    }

    if (timeoutSeconds == 0) 
    {
        std::cerr << "[Warning] connect() timeout is 0. Using default 5s." << std::endl;
        timeoutSeconds = 5;
    }

    try 
    {
        if (!m_sock) 
        {
            try 
            {
                m_sock = std::make_unique<StreamSocket>();
            }
            catch (const std::bad_alloc&) 
            {
                std::cerr << "[Error] Memory allocation failed while creating StreamSocket." << std::endl;
                return eMxErrorCode::OUT_OF_MEMORY;
            }
        }

        SocketAddress address(ip, static_cast<Poco::UInt16>(port));
        Poco::Timespan timeout(static_cast<long>(timeoutSeconds), 0);

        m_sock->connect(address, timeout);

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

// Send raw buffer data over the socket
eMxErrorCode CMx_NonSecureSocket::send(const mx_char* buffer, mx_uint64 len) 
{
    if (!m_sock) 
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
        int sendBufSize = m_sock->getSendBufferSize();
        const mx_char* dataPtr = static_cast<const mx_char*>(buffer);
        size_t totalSent = 0;

        while (totalSent < len) 
        {
            // Calculate how much we can send in this chunk
            int chunkSize = static_cast<int>(
                std::min(len - totalSent, static_cast<size_t>(sendBufSize))
            );

            int n = m_sock->sendBytes(dataPtr + totalSent, chunkSize);

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

// Send a message with length prefix
eMxErrorCode CMx_NonSecureSocket::sendMessage(const std::string& msg) {
    if (msg.empty()) {
        std::cerr << "[Error] sendMessage() called with empty message." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Now send the actual message
    eMxErrorCode errcode = send(reinterpret_cast<const mx_char*>(msg.data()), static_cast<int>(msg.size()));
    if (errcode != eMxErrorCode::NO_ERR) {
        std::cerr << "[Error] Failed to send message body." << std::endl;
        return errcode;
    }

    return eMxErrorCode::NO_ERR; // success
}

// Receive raw data into buffer
eMxErrorCode CMx_NonSecureSocket::receive(mx_char* buffer, mx_uint64 maxLen) {

    if (!m_sock) {
        std::cerr << "[Error] Socket not initialized in receive()." << std::endl;
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    if (!isConnected()) {
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

    // First check if socket is readable
    if (!isReadable(MX_SOCKET_READY_TIMEOUT_MS)) {
        return eMxErrorCode::ERR_SOCKET_NOT_READY_READ;  // no data within timeout
    }
    
    try {

        int recvBufSize = m_sock->getReceiveBufferSize();
        if (recvBufSize <= 0) {
            recvBufSize = MX_RECEVIE_BUFFER_SIZE; // default fallback if system returns 0
        }

        mx_uint64 totalReceived = 0;

        while (totalReceived < maxLen) {
            // Calculate how much to read in this iteration
            mx_uint64 chunkSize = std::min<mx_uint64>(recvBufSize, maxLen - totalReceived);

            int n = m_sock->receiveBytes(buffer + totalReceived, static_cast<int>(chunkSize));

            if (n == 0) {
                std::cerr << "[Info] Connection closed gracefully by peer." << std::endl;
                return (totalReceived > 0) ? eMxErrorCode::NO_ERR : eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }

            totalReceived += n;

            // If less than requested chunk was read, stop (no more data currently available)
            if (n < static_cast<int>(chunkSize)) {
                break;
            }
        }

        return (totalReceived > 0) ? eMxErrorCode::NO_ERR : eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (const Poco::TimeoutException& ex) {
        std::cerr << "[Error] Receive timeout: " << ex.displayText() << std::endl;
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (const Poco::Exception& ex) {
        std::cerr << "[Error] General POCO exception in receive: " << ex.displayText() << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (...) {
        std::cerr << "[Error] Unknown exception in receive()." << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// Receive until end-of-message (EOM) character is found
eMxErrorCode CMx_NonSecureSocket::receiveUntilEOM(std::string& msg) {
    if (!m_sock) 
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

    msg.clear();

    try {
        char ch;
        while (true) {
            int n = m_sock->receiveBytes(&ch, 1); // read 1 byte
            if (n <= 0) {

                if (n == 0) 
                    return eMxErrorCode::ERR_SOCKET_DISCONNECTED; // socket closed

                return eMxErrorCode::UNKNOWN_ERROR;        // error occurred
            }

            msg.push_back(ch); // append received byte

            // check if this byte is the EOM
            if (ch == EOM) {
                break; // End of message
            }
        }

        return eMxErrorCode::NO_ERR;
    } catch (const TimeoutException&) {
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
}

// Check if socket has data available for reading
mx_bool CMx_NonSecureSocket::isReadable(mx_uint64 timeoutMs) {
    if (!m_sock) return false;
    return m_sock->poll(Timespan(0, timeoutMs * 1000), Socket::SELECT_READ);
}

// Check if socket is ready to write
mx_bool CMx_NonSecureSocket::isWritable(mx_uint64 timeoutMs) {
    if (!m_sock) return false;
    return m_sock->poll(Timespan(0, timeoutMs * 1000), Socket::SELECT_WRITE);
}

// Enable/disable blocking mode
eMxErrorCode CMx_NonSecureSocket::setBlocking(mx_bool blocking) {
    try {
        if (m_sock) {
            m_sock->setBlocking(blocking);
        }
        m_bIsBlocking = blocking;
        return eMxErrorCode::NO_ERR;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// Set socket Receive timeout
eMxErrorCode CMx_NonSecureSocket::setReceiveTimeout(mx_uint64 receivetimeoutMs) {
    try {
        if (m_sock) {
            m_sock->setReceiveTimeout(Poco::Timespan(0, receivetimeoutMs * 1000));
        } else {
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
        }
        return eMxErrorCode::NO_ERR;
    } catch (const Poco::Exception& ex) {
        std::cerr << "[Error] setReceiveTimeout failed: " << ex.displayText() << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// Set socket Send timeout
eMxErrorCode CMx_NonSecureSocket::setSendTimeout(mx_uint64 sendtimeoutMs) {
    try {
        if (m_sock) {
            m_sock->setSendTimeout(Poco::Timespan(0, sendtimeoutMs * 1000));
        } else {
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
        }
        return eMxErrorCode::NO_ERR;
    } catch (const Poco::Exception& ex) {
        std::cerr << "[Error] setSendTimeout failed: " << ex.displayText() << std::endl;
        return eMxErrorCode::UNKNOWN_ERROR;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// Set socket Receive buffer
eMxErrorCode CMx_NonSecureSocket::setReceiveBufferSize(mx_uint64 size) {
    try {
        if (m_sock) {
            m_sock->setReceiveBufferSize(size);
            return eMxErrorCode::NO_ERR;
        }
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

// Set socket send buffer
eMxErrorCode CMx_NonSecureSocket::setSendBufferSize(mx_uint64 size) {
    try {
        if (m_sock) {
            m_sock->setSendBufferSize(size);
            return eMxErrorCode::NO_ERR;
        }
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}
// Close socket and clean up resources
eMxErrorCode CMx_NonSecureSocket::close() {
     try {
        if (m_sock) {
            m_sock->close();
            m_sock.reset();
        }
        if (m_server) {
            m_server->close();
            m_server.reset();
        }
        m_bIsConnected = false;
        return eMxErrorCode::NO_ERR;
    } catch (...) {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

}
