#pragma once
#include "CMx_BaseSocket.h"
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/SocketAddress.h>

class CMx_NonSecureSocket : public CMx_BaseSocket {
public:
    CMx_NonSecureSocket();                       // client socket (disconnected)
    explicit CMx_NonSecureSocket(Poco::Net::StreamSocket&& sock); // accepted client
    ~CMx_NonSecureSocket() override;

    // CMx_BaseSocket
    mx_err bind(int port) override;
    mx_err listen() override;
    std::unique_ptr<CMx_BaseSocket> accept() override;
    mx_err connect(const std::string& ip, int port) override;

    mx_err sendBytes(const void* buf, int len, int* sent) override;
    mx_err recvBytes(void* buf, int maxLen, int* recvd) override;

    bool isReadable(int timeoutMs) override;
    bool isWritable(int timeoutMs) override;
    mx_err setBlocking(bool blocking) override;
    mx_err setTimeoutMs(int recvTimeoutMs, int sendTimeoutMs) override;
    mx_err close() override;

    mx_err receiveLengthPrefixed(MxMessage& out) override;
    mx_err receiveDelimiterBased(const std::string& delimiter, MxMessage& out) override;
    mx_err receiveFixedLength(std::size_t N, MxMessage& out) override;

    std::string clientId() const override;

private:
    std::unique_ptr<Poco::Net::ServerSocket> m_server;
    std::unique_ptr<Poco::Net::StreamSocket> m_sock;

    static std::string nowIso8601();
    static mx_err mapSocketExc();
};
