#include "Mx_SecureSocket.h"

// =============================
// Constructor / Destructor
// =============================
CMx_SecureSocket::CMx_SecureSocket()
{
    // Initialize member variables
    _socket = nullptr;
    _server = nullptr;
    _sslContext = nullptr;
}

CMx_SecureSocket::CMx_SecureSocket(mx_bool bisServer) : CMx_BaseSocket(true, bisServer)
{
    // Initialize member variables
    _socket = nullptr;
    _server = nullptr;
    _sslContext = nullptr;
}

CMx_SecureSocket::CMx_SecureSocket(Poco::Net::SecureStreamSocket&& socket)
{
    // Initialize the base class
    m_bIsSSL = true;
    m_bIsServer = false;
    m_bIsBlocking = true;
    m_bIsConnected = true;

    // Initialize the Poco SecureStreamSocket
    _socket = std::make_unique<Poco::Net::SecureStreamSocket>(std::move(socket));
}

CMx_SecureSocket::~CMx_SecureSocket()
{
    // Clean up resources
    close();
}

// =============================
// Bind & Listen (Server)
// =============================

eMxErrorCode CMx_SecureSocket::bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress, mx_bool reusePort, eSslVerificationMode verifyMode)
{
    if (!m_bIsServer)
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Validate port number
    if (port == 0 || port > MX_SOCKET_PORT_MAX)
    {
        return eMxErrorCode::ERR_INVALID_PORT;
    }

    try
    {
        // Dual-stack binding (IPv6 vs IPv4)
        Poco::Net::SocketAddress sa(
            ipMode == eIpBindingMode::IPv6 ? ":::" : "0.0.0.0",
            static_cast<Poco::UInt16>(port));

        // Choose verification mode
        Poco::Net::Context::VerificationMode pocoVerifyMode;
        switch (verifyMode) {
            case eSslVerificationMode::MODE_STRICT:
                pocoVerifyMode = Poco::Net::Context::VERIFY_STRICT;
                break;
            case eSslVerificationMode::MODE_RELAXED:
                pocoVerifyMode = Poco::Net::Context::VERIFY_RELAXED;
                break;
            case eSslVerificationMode::MODE_NONE:
            default:
                pocoVerifyMode = Poco::Net::Context::VERIFY_NONE;
                break;
        }

        _sslContext = new Poco::Net::Context(
            Poco::Net::Context::SERVER_USE,
            "certs-1/server_key.pem",   // server private key
            "certs-1/server_cert.pem",  // server certificate
            "certs-1/ca_cert.pem",      // trusted CA (needed if verifying client certs)
            pocoVerifyMode,           // VERIFY_NONE / VERIFY_RELAXED / VERIFY_STRICT
            9,                        // verification depth
            true,                     // use default cert store
            "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH" // cipher list
        );

        // Secure server socket
        _server = std::make_unique<Poco::Net::SecureServerSocket>(sa, 64, _sslContext);

        if (reuseAddress) _server->setReuseAddress(true);
        if (reusePort)    _server->setReusePort(true);

        m_bIsServer = true;
        m_bIsConnected = false;

        LOG_INFO("Socket bound on port " << port << " with verification mode " << static_cast<int>(verifyMode));
    }
    catch (const Poco::Exception& ex)
    {
        LOG_ERR("Bind failed: " << ex.displayText());
        return eMxErrorCode::ERR_IP_BIND_FAILED;
    }

    return eMxErrorCode::NO_ERR;
}


eMxErrorCode CMx_SecureSocket::listen(mx_uint64 backlog)
{
    // Validate server state
    if (!m_bIsServer)
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    // Validate server socket
    if (!_server)
    {
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    }

    // Check for valid backlog
    if (backlog == 0)
    {
        LOG_WARN("Invalid backlog (0). Using default backlog = MX_DEFAULT_BACKLOG");
        backlog = MX_DEFAULT_BACKLOG;
    }

    try
    {
        // Start listening on the server socket
        _server->listen(static_cast<mx_uint64>(backlog));
    }
    catch (const Poco::Exception& ex)
    {
        LOG_ERR("Listen failed: " << ex.displayText());
        return eMxErrorCode::ERR_SERVICE_START_FAILED;
    }

    return eMxErrorCode::NO_ERR;
}

std::unique_ptr<CMx_BaseSocket> CMx_SecureSocket::accept()
{
    // Validate server state
    if (!m_bIsServer)
    {
        return nullptr;
    }

    // Validate server socket
    if (!_server)
    {
        return nullptr;
    }

    try
    {
        // Accept a new connection
        Poco::Net::SocketAddress clientAddr;
        Poco::Net::SecureStreamSocket clientSocket = _server->acceptConnection(clientAddr);

        // Check if the client socket is valid
        if (!clientSocket.impl()) 
        {
            LOG_ERR("accept() returned invalid client socket");
            return nullptr;
        }

        LOG_INFO("Client connected from " << clientAddr.toString());

        // Create a new secure socket instance
        auto client = std::make_unique<CMx_SecureSocket>(std::move(clientSocket));

        // Set client socket properties
        client->m_bIsConnected = true;
        client->m_bIsSSL = true;
        client->m_bIsServer = false;
        client->m_bIsBlocking = true;

        // Return the new client socket
        return client;
    }
    catch (const Poco::TimeoutException& ex) 
    {
        LOG_WARN("Accept timed out: " << ex.displayText());
        return nullptr;
    }
    catch (const Poco::IOException& ex) 
    {
        LOG_ERR("I/O error during accept: " << ex.displayText());
        return nullptr;
    }
    catch (const Poco::Exception& ex) 
    {
        LOG_ERR("Accept failed: " << ex.displayText());
        return nullptr;
    }
    catch (...) 
    {
        LOG_ERR("Unknown exception in accept()");
        return nullptr;

    }
}

// =============================
// Client Connect
// =============================

eMxErrorCode CMx_SecureSocket::connect(const std::string& ip, 
                                       mx_uint64 port, 
                                       mx_uint64 timeoutSeconds,
                                       eSslVerificationMode verifyMode)
{
    if (m_bIsServer)
        return eMxErrorCode::UNKNOWN_ERROR;


    if (m_bIsConnected)
    {
        LOG_ERR("Socket is already connected");
        return eMxErrorCode::ERR_SOCKET_ALREADY_CONNECTED;
    }

    if (ip.empty())
        return eMxErrorCode::ERR_INVALID_IP_RANGE;
    if (port == 0 || port > MX_SOCKET_PORT_MAX)
        return eMxErrorCode::ERR_INVALID_PORT;

    try
    {
        // Map custom enum -> Poco verification mode
        Poco::Net::Context::VerificationMode pocoVerifyMode;
        switch (verifyMode) {
            case eSslVerificationMode::MODE_STRICT:
                pocoVerifyMode = Poco::Net::Context::VERIFY_STRICT;
                break;
            case eSslVerificationMode::MODE_RELAXED:
                pocoVerifyMode = Poco::Net::Context::VERIFY_RELAXED;
                break;
            case eSslVerificationMode::MODE_NONE:
            default:
                pocoVerifyMode = Poco::Net::Context::VERIFY_NONE;
                break;
        }

        _sslContext = new Poco::Net::Context(
            Poco::Net::Context::CLIENT_USE,
            "certs/client_key.pem",   // Client private key
            "certs/client_cert.pem",  // Client certificate
            "certs/ca_cert.pem",      // Trusted CA certs
            pocoVerifyMode,           // VERIFY_NONE, VERIFY_RELAXED, VERIFY_STRICT
            9,                        // Verification depth
            true                      // Use default certificate store
        );


        _socket = std::make_unique<Poco::Net::SecureStreamSocket>(_sslContext);

        Poco::Net::SocketAddress address(ip, static_cast<Poco::UInt16>(port));
        Poco::Timespan timeout(static_cast<long>(timeoutSeconds), 0);


        _socket->connect(address, timeout);

        _socket->setBlocking(true);
        m_bIsConnected = true;
        m_bIsServer = false;

        LOG_INFO("Connected to " << ip << ":" << port 
                 << " with verification mode " << static_cast<int>(verifyMode));
    }
    catch (const Poco::Net::ConnectionRefusedException&)
    {
        LOG_ERR("Connection refused");
        return eMxErrorCode::ERR_CONNECTION_FAILED;
    }
    catch (const Poco::TimeoutException&)
    {
        LOG_ERR("Connection timed out");
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (const Poco::Exception& ex)
    {
        LOG_ERR("Connect failed: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    return eMxErrorCode::NO_ERR;
}

// =============================
// Data Send
// =============================

eMxErrorCode CMx_SecureSocket::send(const mx_char* buffer, mx_uint64 len)
{
    if (!_socket || !buffer || len == 0)
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

    if (!isConnected()) 
    {
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;  // socket is not connected
    }

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
                std::min(static_cast<mx_uint64>(len - totalSent), static_cast<mx_uint64>(sendBufSize))
            );

            int n = _socket->sendBytes(dataPtr + totalSent, chunkSize);

            if (n <= 0) {
                LOG_WARN("Send failed or socket closed (sent=" << n << ")");
                m_bIsConnected = false;
                return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }

            totalSent += n;
        }
    }
    catch (...)
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    return eMxErrorCode::NO_ERR;
}

eMxErrorCode CMx_SecureSocket::sendMessage(const std::string& msg)
{
    if (msg.empty())
        return eMxErrorCode::UNKNOWN_ERROR; // no data to send

   // Now send the actual message
    eMxErrorCode errcode = send(reinterpret_cast<const mx_char*>(msg.data()), static_cast<int>(msg.size()));
    if (errcode != eMxErrorCode::NO_ERR) 
    {
        LOG_ERR("Failed to send message body");
        return errcode;
    }
    return eMxErrorCode::NO_ERR; // all data sent successfully
   
}


// =============================
// Data Receive
// =============================

eMxErrorCode CMx_SecureSocket::receive(mx_char* buffer, mx_uint64 maxLen)
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
            recvBufSize = MX_RECEIVE_BUFFER_SIZE; // default fallback if system returns 0

        mx_uint64 totalReceived = 0;

        while (totalReceived < maxLen) 
        {
            // Calculate how much to read in this iteration
            mx_uint64 chunkSize = std::min(static_cast<mx_uint64>(recvBufSize),static_cast<mx_uint64> (maxLen - totalReceived));

            int n = _socket->receiveBytes(buffer + totalReceived, static_cast<int>(chunkSize));

            if (n == 0) 
            {
                LOG_INFO("Connection closed by peer");
                return (totalReceived > 0) ? eMxErrorCode::NO_ERR : eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }

            totalReceived += n;

            // If less than requested chunk was read, stop (no more data currently available)
            if (n < static_cast<int>(chunkSize))
                break;
        
        }

        return (totalReceived > 0) ? eMxErrorCode::NO_ERR : eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (const Poco::TimeoutException&)
    {
        return eMxErrorCode::ERR_CONNECTION_TIME_OUT;
    }
    catch (...)
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    return eMxErrorCode::NO_ERR;
}

eMxErrorCode CMx_SecureSocket::receiveUntilEOM(std::string& msg)
{
    if (!_socket)
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    if (!isConnected()) 
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;

    try
    {
        mx_char c;
        while (true)
        {
            LOG_ERR("receiveUntilEOM exception: ");
            int received = _socket->receiveBytes(&c, 1); // read 1 byte
            if (received > 0)
            {
                msg.push_back(static_cast<char>(c));

                if (c == EOM) // stop on EOM
                    return eMxErrorCode::NO_ERR;
            }
            else
            {
                return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
            }
        }
    }
    catch (const Poco::Exception& ex)
    {
        LOG_ERR("receiveUntilEOM exception: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (const std::exception& ex)
    {
        LOG_ERR("std::exception: " << ex.what());
        return eMxErrorCode::UNKNOWN_ERROR;
    }
    catch (...)
    {
        LOG_ERR("Unknown exception in receiveUntilEOM()");
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    return eMxErrorCode::NO_ERR;
}


// =============================
// Status Check
// =============================

mx_bool CMx_SecureSocket::isReadable(mx_uint64 timeoutMs)
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

mx_bool CMx_SecureSocket::isWritable(mx_uint64 timeoutMs)
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

// =============================
// Config
// =============================

eMxErrorCode CMx_SecureSocket::setBlocking(mx_bool blocking)
{
    if (!_socket)
        return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

    try
    {
        _socket->setBlocking(blocking);
         m_bIsBlocking = blocking;
    }
    catch (...)
    {
        return eMxErrorCode::UNKNOWN_ERROR;
    }

    return eMxErrorCode::NO_ERR;
}

// =============================
// Close
// =============================

eMxErrorCode CMx_SecureSocket::close()
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
    }
    catch (...)
    {
        return eMxErrorCode::ERR_SOCKET_DISCONNECTED;
    }

    return eMxErrorCode::NO_ERR;
}

// =============================
// SSL Certificate Handling
// =============================

Poco::Crypto::X509Certificate CMx_SecureSocket::getPeerCertificate() const
{
    if (!_socket || !m_bIsConnected)
        throw std::runtime_error("No peer certificate available");
    return _socket->peerCertificate();
}

eMxErrorCode CMx_SecureSocket::verifyPeerCertificate() const
{
    try
    {
        if (_socket && m_bIsConnected)
        {
            Poco::Crypto::X509Certificate cert = _socket->peerCertificate();
            if (!cert.subjectName().empty())
                return eMxErrorCode::NO_ERR;
        }
        return eMxErrorCode::ERR_SSL_PEER_VERIFICATION_FAILED;
    }
    catch (...)
    {
        return eMxErrorCode::ERR_SSL_PEER_VERIFICATION_FAILED;
    }
}

std::string CMx_SecureSocket::getPeerCommonName() const
{
    if (!_socket || !m_bIsConnected) return {};
    try
    {
        return _socket->peerCertificate().commonName();
    }
    catch (...)
    {
        return {};
    }
}

std::chrono::system_clock::time_point CMx_SecureSocket::getPeerCertExpiry() const
{
    if (!_socket || !m_bIsConnected)
        return {};

    try
    {
        Poco::Net::X509Certificate netCert = _socket->peerCertificate();
        Poco::DateTime dt = netCert.expiresOn();  // correct method
        Poco::Timestamp ts = dt.timestamp();
        return std::chrono::system_clock::from_time_t(ts.epochTime());
    }
    catch (...)
    {
        return {};
    }
}


/// Set receive timeout
eMxErrorCode CMx_SecureSocket::setReceiveTimeout(mx_uint64 receivetimeoutMs)
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
        
        _socket->setReceiveTimeout(Poco::Timespan(receivetimeoutMs * 1000));

        return eMxErrorCode::NO_ERR;
    } 
    catch (const Poco::Exception& ex) { LOG_ERR("setReceiveTimeout failed: " << ex.displayText()); return eMxErrorCode::UNKNOWN_ERROR; }
    catch (...) { return eMxErrorCode::UNKNOWN_ERROR; }
}

/// Set send timeout (milliseconds)
eMxErrorCode CMx_SecureSocket::setSendTimeout(mx_uint64 sendtimeoutMs) 
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

        _socket->setSendTimeout(Poco::Timespan(sendtimeoutMs * 1000));
        LOG_INFO("Send timeout set to " << sendtimeoutMs << " ms");

        return eMxErrorCode::NO_ERR;

    } catch (const Poco::Exception& ex) 
    {
        LOG_ERR("setSendTimeout failed: " << ex.displayText());
        return eMxErrorCode::UNKNOWN_ERROR;
    } catch (...) 
    {
        LOG_ERR("setSendTimeout failed: Unknown exception");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/// Set receive buffer size (bytes)
eMxErrorCode CMx_SecureSocket::setReceiveBufferSize(mx_uint64 size) 
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;

        _socket->setReceiveBufferSize(size);
        LOG_INFO("Receive buffer size set to " << size);

        return eMxErrorCode::NO_ERR;

    } catch (...) {
        LOG_ERR("setReceiveBufferSize failed: Unknown exception");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

/// Set send buffer size
eMxErrorCode CMx_SecureSocket::setSendBufferSize(mx_uint64 size) 
{
    try 
    {
        if (!_socket)
            return eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED;
    
        _socket->setSendBufferSize(size);
        LOG_INFO("Send buffer size set to " << size);

        return eMxErrorCode::NO_ERR;

    } catch (...) 
    {
        LOG_ERR("setSendBufferSize failed: Unknown exception");
        return eMxErrorCode::UNKNOWN_ERROR;
    }
}

std::string CMx_SecureSocket::getPeerAddress() {
    if (_socket)
    return _socket->peerAddress().toString();
    LOG_WARN("getPeerAddress called but socket not initialized");
    return "";
}
