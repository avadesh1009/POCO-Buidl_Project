#ifndef CMX_BASESOCKET_H
#define CMX_BASESOCKET_H

#include <string>
#include <memory>
#include <chrono>
#include "Mx_ErrorCodes.h"
#include "mx_types.h"
#include "Mx_Defines.h"

// temporary put here update at common place
#define MX_SOCKET_CONNECTION_TIMEOUT    8000
#define MX_DEFAULT_BACKLOG              64
#define MX_RECEVIE_BUFFER_SIZE          16 * 1000  
#define MX_SEND_BUFFER_SIZE             16 * 1000  
#define MX_SOCKET_READY_TIMEOUT_MS      1
/**
 * @enum eIpBindingMode
 * @brief Specifies the IP mode for the socket.
 */
enum class eIpBindingMode 
{
    IPv4 = 1,
    IPv6 = 2,
    DualStack = 3
};

/**
 * @class CMx_BaseSocket
 * @brief Abstract base class for both SSL and non-SSL sockets.
 * 
 * Provides a unified interface for server and client sockets.
 * Derived classes should implement platform-specific or protocol-specific
 * socket operations.
 */
class CMx_BaseSocket
{
    protected:
        mx_bool m_bIsConnected; 
        mx_bool m_bIsSSL;       
        mx_bool m_bIsServer;    
        mx_bool m_bIsBlocking; 

    private:
        /**
         * @brief Resets the socket state to default values.
         *
         * - Connection: false (not connected)
         * - SSL: false (plain socket by default)
         * - Server mode: false (client by default)
         * - Blocking: true (blocking mode enabled)
         */
        void reset();


    public:

        /**
         * @brief Default constructor.
         * Initializes all flags to false.
         */
        CMx_BaseSocket();

        /**
         * @brief Parameterized constructor.
         * @param bIsSSL Whether the socket should use SSL/TLS.
         * @param bIsServer Whether the socket should operate as a server.
         */
        CMx_BaseSocket(mx_bool bisSSL, mx_bool bisServer);

        /**
         * @brief Virtual destructor.
         */
        virtual ~CMx_BaseSocket();

        /**
         * @brief Check if the socket is in blocking mode.
         * @return true if blocking, false otherwise.
         */
        mx_bool isBlocking() const { return m_bIsBlocking; }

        /**
         * @brief Check if the socket is connected.
         * @return true if connected, false otherwise.
         */
        mx_bool isConnected() const { return m_bIsConnected; }

        /**
         * @brief Check if the socket uses SSL/TLS.
         * @return true if SSL/TLS is enabled, false otherwise.
         */
        mx_bool isSSL() const { return m_bIsSSL; }

        /**
         * @brief Check if the socket is running as a server.
         * @return true if server mode, false otherwise.
         */
        mx_bool isServer() const { return m_bIsServer; }

        /**
         * @brief Bind the socket to a specific port.
         * @param port Port number to bind to.
         * @param ipMode IP binding mode (IPv4, IPv6, DualStack).
         * @param reuseAddress Whether to allow address reuse.
         * @param reusePort Whether to allow port reuse.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress = true, mx_bool reusePort = false) = 0;

        /**
         * @brief Start listening for incoming connections.
         * @param backlog Maximum length of the queue of pending connections.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode listen(mx_uint64 backlog = MX_DEFAULT_BACKLOG) = 0;

        /**
         * @brief Accept an incoming connection.
         * @return A unique pointer to the accepted socket instance.
         */
        virtual std::unique_ptr<CMx_BaseSocket> accept() = 0;

        /**
         * @brief Connect to a remote host.
         * @param ip IP address of the remote host.
         * @param port Port number of the remote host.
         * @param timeoutSeconds Connection timeout in seconds.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode connect(const std::string& ip, mx_uint64 port, mx_uint64 timeoutSeconds = MX_SOCKET_CONNECTION_TIMEOUT) = 0;

        /**
         * @brief Send raw data over the socket.
         * @param buffer Pointer to the data buffer.
         * @param len Length of the data in bytes.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode send(const mx_char* buffer, mx_uint64 len) = 0;

        /**
         * @brief Send a string message over the socket.
         * @param msg The message to send.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode sendMessage(const std::string& msg) = 0;

        /**
         * @brief Receive raw data from the socket.
         * @param buffer Pointer to the buffer to store data.
         * @param maxLen Maximum length of data to read.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode receive(mx_char* buffer, mx_uint64 maxLen) = 0;

        /**
         * @brief Receive data until an End Of Message (EOM) marker.
         * @param msg String to store the received message.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode receiveUntilEOM(std::string& msg) = 0;

        /**
         * @brief Check if the socket is readable within a timeout.
         * @param timeoutMs Timeout in milliseconds.
         * @return true if readable, false otherwise.
         */
        virtual mx_bool isReadable(mx_uint64 timeoutMs) = 0;

        /**
         * @brief Check if the socket is writable within a timeout.
         * @param timeoutMs Timeout in milliseconds.
         * @return true if writable, false otherwise.
         */
        virtual mx_bool isWritable(mx_uint64 timeoutMs) = 0;

        /**
         * @brief Set the socket's blocking mode.
         * @param blocking true to enable blocking mode, false for non-blocking.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode setBlocking(mx_bool blocking) = 0;

        /**
         * @brief Set the socket's Receive buffer timeout.
         * @param timeoutMs Timeout in milliseconds.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode setReceiveTimeout(mx_uint64 receivetimeoutMs) = 0;

        /**
         * @brief Set the socket's send buffer timeout.
         * @param timeoutMs Timeout in milliseconds.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode setSendTimeout(mx_uint64 sendtimeoutMs) = 0;

        /**
         * @brief Set socket receive buffer size.
         * @param size Buffer size in bytes.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode setReceiveBufferSize(mx_uint64 size) = 0;

        /**
         * @brief Set socket send buffer size.
         * @param size Buffer size in bytes.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode setSendBufferSize(mx_uint64 size) = 0;

        /**
         * @brief Close the socket.
         * @return Error code (0 for success).
         */
        virtual eMxErrorCode close() = 0;
};

#endif // CMX_BASESOCKET_H