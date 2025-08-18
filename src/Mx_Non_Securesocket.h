#pragma once
#include "Mx_BaseSocket.h"
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/SocketAddress.h>

class CMx_NonSecureSocket : public CMx_BaseSocket {

private:

    /**
     * @brief Server socket instance (valid only when running as a server).
     */
    std::unique_ptr<Poco::Net::ServerSocket> m_server;

    /**
     * @brief Stream socket instance (used for client connection or accepted peer).
     */
    std::unique_ptr<Poco::Net::StreamSocket> m_sock;

public:

    /**
     * @brief Default constructor for a client socket (disconnected state).
     */
    CMx_NonSecureSocket();

    /**
     * @brief Constructor for an accepted client socket.
     * @param sock The Poco StreamSocket representing the accepted client.
     */
    explicit CMx_NonSecureSocket(Poco::Net::StreamSocket&& sock);

    /**
     * @brief Destructor.
     */
    ~CMx_NonSecureSocket() override;

public:

    // ---------------- Server-side API ----------------


    /**
     * @brief Create and bind the server socket.
     * @param port Port number to bind to.
     * @param ipMode IP binding mode (IPv4, IPv6, DualStack).
     * @param reuseAddress Allow address reuse.
     * @param reusePort Allow port reuse (if supported).
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode bind(mx_uint64 port, eIpBindingMode ipMode, mx_bool reuseAddress = true, mx_bool reusePort = false) override;

    /**
     * @brief Start listening for incoming connections.
     * @param backlog Size of the pending connection queue.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode listen(mx_uint64 backlog = MX_DEFAULT_BACKLOG) override;

    /**
     * @brief Accept an incoming client connection.
     * @return A unique pointer to the accepted client socket.
     */
    std::unique_ptr<CMx_BaseSocket> accept() override;


    // ---------------- Client-side API ----------------


    /**
     * @brief Connect to a remote server.
     * @param ip Server IP address.
     * @param port Server port.
     * @param timeoutSeconds Connection timeout in seconds.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode connect(const std::string& ip, mx_uint64 port, mx_uint64 timeoutSeconds = MX_SOCKET_CONNECTION_TIMEOUT) override;


    // ---------------- Data Transfer API ----------------


    /**
     * @brief Send raw data over the socket.
     * @param buffer Pointer to the data buffer.
     * @param len Length of the data.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode send(const mx_char* buffer, mx_uint64 len) override;

    /**
     * @brief Send a string message over the socket.
     * @param msg The message string to send.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode sendMessage(const std::string& msg) override;

    /**
     * @brief Receive raw data from the socket.
     * @param buffer Destination buffer to store received data.
     * @param maxLen Maximum number of bytes to receive.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode receive(mx_char* buffer, mx_uint64 maxLen) override;

    /**
     * @brief Receive data until an End Of Message (EOM) marker.
     * @param msg Destination string to store received data.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode receiveUntilEOM(std::string& msg) override;


    // ---------------- State Checks ----------------


    /**
     * @brief Check if the socket is readable within the timeout.
     * @param timeoutMs Timeout in milliseconds.
     * @return true if readable, false otherwise.
     */
    mx_bool isReadable(mx_uint64 timeoutMs) override;

    /**
     * @brief Check if the socket is writable within the timeout.
     * @param timeoutMs Timeout in milliseconds.
     * @return true if writable, false otherwise.
     */
    mx_bool isWritable(mx_uint64 timeoutMs) override;


    // ---------------- Configuration API ----------------


    /**
     * @brief Set the socket to blocking or non-blocking mode.
     * @param blocking true for blocking, false for non-blocking.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode setBlocking(mx_bool blocking) override;

    /**
     * @brief Set socket Receive buffer timeout.
     * @param receivetimeoutMs Timeout in milliseconds.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode setReceiveTimeout(mx_uint64 receivetimeoutMs) override;

    /**
     * @brief Set socket send buffer timeout.
     * @param sendtimeoutMs Timeout in milliseconds.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode setSendTimeout(mx_uint64 sendtimeoutMs) override;

    /**
     * @brief Set socket receive buffer size.
     * @param size Buffer size in bytes.
     * @return Error code (NO_ERROR on success).
     */
    virtual eMxErrorCode setReceiveBufferSize(mx_uint64 size) override;

    /**
     * @brief Set socket send buffer size.
     * @param size Buffer size in bytes.
     * @return Error code (NO_ERROR on success).
     */
    virtual eMxErrorCode setSendBufferSize(mx_uint64 size) override;

    // ---------------- Cleanup ----------------


    /**
     * @brief Close the socket and release resources.
     * @return Error code (NO_ERROR on success).
     */
    eMxErrorCode close() override;

};
