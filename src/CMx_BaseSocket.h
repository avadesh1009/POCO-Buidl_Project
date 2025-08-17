#pragma once
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

enum class mx_err {
    ok = 0,
    would_block,
    timeout,
    disconnected,
    invalid_arg,
    io_error,
    not_ready,
    unknown
};

enum class mx_recv_mode {
    length_prefixed,  // [u32 length][payload]
    delimiter_based,  // payload... [delimiter bytes]
    fixed_length      // read exactly N bytes
};

struct MxMessage {
    std::string clientId;   // e.g., "10.0.0.5:52344"
    std::string data;       // raw bytes (may contain '\0')
    std::string iso8601Ts;  // when received
};

enum class IPMode {
    IPv4 = 1,
    IPv6,
    DualStack
};

class CMx_BaseSocket {
protected:
    bool m_bIsConnected;
    bool m_bIsSSL;
    bool m_bIsServer;
    bool m_bIsBlocking;

public:
    CMx_BaseSocket();
    CMx_BaseSocket(bool isSSL, bool isServer);
    virtual ~CMx_BaseSocket();

    // reset function
    virtual void reset();

    // flags
    inline bool isConnected() const { return m_bIsConnected; }
    inline bool isBlocking()  const { return m_bIsBlocking; }
    inline bool isSSL()       const { return m_bIsSSL; }
    inline bool isServer()    const { return m_bIsServer; }

    // server side
    virtual void bind(int port,IPMode ipMode, bool reuseAddress = true,bool reusePort = false) = 0;
    virtual void listen(int backlog = 64) = 0;
    virtual std::unique_ptr<CMx_BaseSocket> accept() = 0;

    // client side
    virtual bool  connect(const std::string& ip, int port, int timeoutSeconds = 8000) = 0;

    // io
    virtual mx_err send(const char* buf, int len) = 0;
    virtual mx_err sendMessage(const std::string& msg) = 0;

    virtual mx_err receive(char* buf, int maxLen) = 0;
    virtual mx_err receiveUntilEOM(std::string& msg) = 0;


    // helpers
    virtual bool isReadable(int timeoutMs) = 0;
    virtual bool isWritable(int timeoutMs) = 0;
    virtual mx_err setBlocking(bool blocking) = 0;
    virtual mx_err setTimeoutMs(int TimeoutMs) = 0;
    virtual mx_err close() = 0;
};
