#ifndef CMX_SECURESOCKET_H
#define CMX_SECURESOCKET_H

#include "Mx_BaseSocket.h"
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/Context.h>
#include <Poco/Crypto/X509Certificate.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SocketAddress.h>
#include <memory>
#include <string>
#include <chrono>

// ============================================================================
// Logging macros
// ============================================================================
#define LOG_INFO(msg)   std::cout << "[info] "  << msg << std::endl
#define LOG_DEBUG(msg)  std::cout << "[debug] " << msg << std::endl
#define LOG_WARN(msg)   std::cout << "[warn] "  << msg << std::endl
#define LOG_ERR(msg)    std::cerr << "[err] "   << msg << std::endl

// ============================================================================
// Secure Socket Class
// ============================================================================
class CMx_SecureSocket : public CMx_BaseSocket
{
    private:
        std::unique_ptr<Poco::Net::SecureStreamSocket> _socket;  
        std::unique_ptr<Poco::Net::SecureServerSocket> _server;  
        Poco::Net::Context::Ptr _sslContext;                     

    public:
        // --------------------------------------------------------------------
        // Constructors / Destructor
        // --------------------------------------------------------------------

        /**
         * @brief Default constructor.
         */
        CMx_SecureSocket();

        /**
         * @brief Construct with server flag.
         * @param isServer True if this is server socket.
         */
        explicit CMx_SecureSocket(mx_bool isServer);

        /**
         * @brief Construct from existing Poco SecureStreamSocket.
         * @param socket SecureStreamSocket instance.
         */
        explicit CMx_SecureSocket(Poco::Net::SecureStreamSocket&& socket);

        /**
         * @brief Destructor.
         */
        ~CMx_SecureSocket() override;

        // --------------------------------------------------------------------
        // Server-side APIs
        // --------------------------------------------------------------------

        /**
         * @brief Bind the secure socket to a specific port.
         * @param port Port number to bind to.
         * @param ipMode IP binding mode (IPv4/IPv6).
         * @param reuseAddress Flag to enable/disable address reuse.
         * @param reusePort Flag to enable/disable port reuse.
         * @return Error code (0 for success).
         */
        eMxErrorCode bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress = true, mx_bool reusePort = false) override;

        /**
         * @brief Start listening for incoming connections.
         * @param backlog Maximum number of pending connections.
         * @return Error code (0 for success).
         */
        eMxErrorCode listen(mx_uint64 backlog = MX_DEFAULT_BACKLOG) override;

        /**
         * @brief Accept an incoming secure connection.
         * @return A unique pointer to a new CMx_SecureSocket instance.
         */
        std::unique_ptr<CMx_BaseSocket> accept() override;

        // --------------------------------------------------------------------
        // Client-side APIs
        // --------------------------------------------------------------------

        /**
         * @brief Connect to a remote secure server.
         * @param ip Remote IP address.
         * @param port Remote port number.
         * @param timeoutMs Connection timeout in milliseconds.
         * @return Error code (0 for success).
         */
        eMxErrorCode connect(const std::string& ip, mx_uint64 port, mx_uint64 timeoutMs = MX_SOCKET_CONNECTION_TIMEOUT) override;

        // --------------------------------------------------------------------
        // Data I/O
        // --------------------------------------------------------------------

        /**
         * @brief Send raw data securely.
         * @param buffer Pointer to the data buffer.
         * @param len Length of the data in bytes.
         * @return Error code (0 for success).
         */
        eMxErrorCode send(const mx_char* buffer, mx_uint64 len) override;

        /**
         * @brief Send a string message securely.
         * @param msg Message string to send.
         * @return Error code (0 for success).
         */
        eMxErrorCode sendMessage(const std::string& msg) override;

        /**
         * @brief Receive raw data securely.
         * @param buffer Buffer to store received data.
         * @param maxLen Maximum length to read.
         * @return Error code (0 for success).
         */
        eMxErrorCode receive(mx_char* buffer, mx_uint64 maxLen) override;

        /**
         * @brief Receive data until End Of Message (EOM) marker.
         * @param msg String to store the received message.
         * @return Error code (0 for success).
         */
        eMxErrorCode receiveUntilEOM(std::string& msg) override;

        // --------------------------------------------------------------------
        // Socket State / Config
        // --------------------------------------------------------------------

        /**
         * @brief Check if the socket is readable.
         * @param timeoutMs Timeout in milliseconds.
         * @return True if readable, false otherwise.
         */
        mx_bool isReadable(mx_uint64 timeoutMs) override;

        /**
         * @brief Check if the socket is writable.
         * @param timeoutMs Timeout in milliseconds.
         * @return True if writable, false otherwise.
         */
        mx_bool isWritable(mx_uint64 timeoutMs) override;

        /**
         * @brief Set blocking mode for the socket.
         * @param blocking True for blocking, false for non-blocking.
         * @return Error code (0 for success).
         */
        eMxErrorCode setBlocking(mx_bool blocking) override;

        /**
         * @brief Close the secure socket.
         * @return Error code (0 for success).
         */
        eMxErrorCode close() override;

        /**
         * @brief Set socket receive timeout.
         * @param timeoutMs Timeout in milliseconds.
         * @return Error code (0 for success).
         */
        eMxErrorCode setReceiveTimeout(mx_uint64 timeoutMs) override;

        /**
         * @brief Set socket send timeout.
         * @param timeoutMs Timeout in milliseconds.
         * @return Error code (0 for success).
         */
        eMxErrorCode setSendTimeout(mx_uint64 timeoutMs) override;

        /**
         * @brief Set socket receive buffer size.
         * @param size Buffer size in bytes.
         * @return Error code (0 for success).
         */
        eMxErrorCode setReceiveBufferSize(mx_uint64 size) override;

        /**
         * @brief Set socket send buffer size.
         * @param size Buffer size in bytes.
         * @return Error code (0 for success).
         */
        eMxErrorCode setSendBufferSize(mx_uint64 size) override;

        // --------------------------------------------------------------------
        // Certificate Handling
        // --------------------------------------------------------------------

        /**
         * @brief Retrieve the peer's SSL certificate.
         * @return Peer certificate as Poco::Crypto::X509Certificate.
         */
        Poco::Crypto::X509Certificate getPeerCertificate() const;

        /**
         * @brief Verify the peer's SSL certificate against trusted CA list.
         * @return Error code (0 for success).
         */
        eMxErrorCode verifyPeerCertificate() const;

        /**
         * @brief Get the Common Name (CN) from the peer's certificate.
         * @return CN string.
         */
        std::string getPeerCommonName() const;

        /**
         * @brief Get the expiration date of the peer's certificate.
         * @return Expiration time as std::chrono::system_clock::time_point.
         */
        std::chrono::system_clock::time_point getPeerCertExpiry() const;

        // --------------------------------------------------------------------
        // Helpers
        // --------------------------------------------------------------------

        /**
         * @brief Create an SSL context for secure communication.
         * @param certFile Path to certificate file.
         * @param keyFile Path to private key file.
         * @param caLocation Path to CA location.
         * @param mode Verification mode (default: VERIFY_RELAXED).
         * @return SSL context pointer.
         */
        static Poco::Net::Context::Ptr createSSLContext(const std::string& certFile, const std::string& keyFile, const std::string& caLocation, Poco::Net::Context::VerificationMode mode = Poco::Net::Context::VERIFY_RELAXED);

        std::string getPeerAddress();
};

#endif // CMX_SECURESOCKET_H
