#pragma once
#include "CMx_BaseSocket.h"
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/SocketAddress.h>

class CMx_NonSecureSocket : public CMx_BaseSocket {
private:
    std::unique_ptr<Poco::Net::ServerSocket> m_server;
    std::unique_ptr<Poco::Net::StreamSocket> m_sock;

public:
    CMx_NonSecureSocket();                       // client socket (disconnected)
    explicit CMx_NonSecureSocket(Poco::Net::StreamSocket&& sock); // accepted client
    ~CMx_NonSecureSocket() override;

public:

    // Server-side Api
    // Create and bind server socket (IPv4, IPv6, DualStack)
    void createServerSocket(int port, IPMode ipMode, bool reuseAddress = true, bool reusePort = false);
    void bind(int port, IPMode ipMode, bool reuseAddress = true,bool reusePort = false) override;
    void listen(int backlog = 64) override;
    std::unique_ptr<CMx_BaseSocket> accept() override;

    // Client-side Api  
    bool  connect(const std::string& ip, int port, int timeoutSeconds = 8000) override;

    // Send Data Api
    virtual mx_err send(const char* buf, int len);
    virtual mx_err sendMessage(const std::string& msg);

    // Receive Data Api
    mx_err receive(char* buf, int maxLen) override;
    mx_err receiveUntilEOM(std::string& msg) override;

    // check socket state
    bool isReadable(int timeoutMs) override;
    bool isWritable(int timeoutMs) override;

    // Set Api 
    mx_err setBlocking(bool blocking) override;
    mx_err setTimeoutMs(int TimeoutMs) override;

    // close socket Api
    mx_err close() override;
    
};
