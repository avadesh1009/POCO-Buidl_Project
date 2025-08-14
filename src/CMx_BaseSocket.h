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

class CMx_BaseSocket {
protected:
    bool m_bIsConnected{false};
    bool m_bIsSSL{false};
    bool m_bIsServer{false};
    bool m_bIsBlocking{true};

public:
    CMx_BaseSocket() = default;
    CMx_BaseSocket(bool isSSL, bool isServer)
        : m_bIsSSL(isSSL), m_bIsServer(isServer) {}
    virtual ~CMx_BaseSocket() = default;

    // flags
    bool isConnected() const { return m_bIsConnected; }
    bool isBlocking()  const { return m_bIsBlocking; }
    bool isSSL()       const { return m_bIsSSL; }
    bool isServer()    const { return m_bIsServer; }

    // server side
    virtual mx_err bind(int port) = 0;
    virtual mx_err listen() = 0;
    virtual std::unique_ptr<CMx_BaseSocket> accept() = 0;

    // client side
    virtual mx_err connect(const std::string& ip, int port) = 0;

    // io
    virtual mx_err sendBytes(const void* buf, int len, int* sent = nullptr) = 0;
    virtual mx_err recvBytes(void* buf, int maxLen, int* recvd = nullptr) = 0;

    // helpers
    virtual bool isReadable(int timeoutMs) = 0;
    virtual bool isWritable(int timeoutMs) = 0;
    virtual mx_err setBlocking(bool blocking) = 0;
    virtual mx_err setTimeoutMs(int recvTimeoutMs, int sendTimeoutMs) = 0;
    virtual mx_err close() = 0;

    // high-level receive variants (implemented in derived, but shared signature)
    virtual mx_err receiveLengthPrefixed(MxMessage& out) = 0;               // [u32 len][payload]
    virtual mx_err receiveDelimiterBased(const std::string& delimiter, MxMessage& out) = 0;
    virtual mx_err receiveFixedLength(std::size_t N, MxMessage& out) = 0;

    // convenience
    virtual mx_err sendString(const std::string& s) {
        return sendBytes(s.data(), static_cast<int>(s.size()), nullptr);
    }

    // client id (ip:port) string for logging; empty if not connected
    virtual std::string clientId() const = 0;
};
