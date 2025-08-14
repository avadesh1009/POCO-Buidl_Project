#include "CMx_Non_SecureSocket.h"
#include <Poco/Timestamp.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timespan.h>
#include <Poco/Exception.h>
#include <cstring>

using namespace Poco;
using namespace Poco::Net;

static inline mx_err mapException(const std::exception* e) {
    // You can refine this mapping if you want more fidelity
    return mx_err::io_error;
}

CMx_NonSecureSocket::CMx_NonSecureSocket()
    : CMx_BaseSocket(false, false) {}

CMx_NonSecureSocket::CMx_NonSecureSocket(StreamSocket&& sock)
    : CMx_BaseSocket(false, false),
      m_sock(std::make_unique<StreamSocket>(std::move(sock))) {
    m_bIsConnected = true;
}

CMx_NonSecureSocket::~CMx_NonSecureSocket() { close(); }

mx_err CMx_NonSecureSocket::bind(int port) {
    try {
        m_server = std::make_unique<ServerSocket>(SocketAddress("0.0.0.0", port));
        m_bIsServer = true;
        return mx_err::ok;
    } catch (const std::exception& e) {
        return mapException(&e);
    }
}

mx_err CMx_NonSecureSocket::listen() {
    try {
        if (!m_server) return mx_err::not_ready;
        m_server->listen();
        return mx_err::ok;
    } catch (const std::exception& e) {
        return mapException(&e);
    }
}

std::unique_ptr<CMx_BaseSocket> CMx_NonSecureSocket::accept() {
    if (!m_server) return {};
    try {
        StreamSocket client = m_server->acceptConnection();
        return std::make_unique<CMx_NonSecureSocket>(std::move(client));
    } catch (...) {
        return {};
    }
}

mx_err CMx_NonSecureSocket::connect(const std::string& ip, int port) {
    try {
        m_sock = std::make_unique<StreamSocket>();
        m_sock->connect(SocketAddress(ip, port));
        m_bIsConnected = true;
        m_bIsServer = false;
        return mx_err::ok;
    } catch (const std::exception& e) {
        return mapException(&e);
    }
}

mx_err CMx_NonSecureSocket::sendBytes(const void* buf, int len, int* sent) {
    if (!m_sock) return mx_err::not_ready;
    try {
        int n = m_sock->sendBytes(buf, len);
        if (sent) *sent = n;
        return mx_err::ok;
    } catch (const TimeoutException&) {
        return mx_err::timeout;
    } catch (const std::exception& e) {
        return mapException(&e);
    }
}

mx_err CMx_NonSecureSocket::recvBytes(void* buf, int maxLen, int* recvd) {
    if (!m_sock) return mx_err::not_ready;
    try {
        int n = m_sock->receiveBytes(buf, maxLen);
        if (recvd) *recvd = n;
        if (n == 0) return mx_err::disconnected;
        return mx_err::ok;
    } catch (const TimeoutException&) {
        return mx_err::timeout;
    } catch (const std::exception& e) {
        return mapException(&e);
    }
}

bool CMx_NonSecureSocket::isReadable(int timeoutMs) {
    if (!m_sock) return false;
    return m_sock->poll(Timespan(0, timeoutMs * 1000), Socket::SELECT_READ);
}
bool CMx_NonSecureSocket::isWritable(int timeoutMs) {
    if (!m_sock) return false;
    return m_sock->poll(Timespan(0, timeoutMs * 1000), Socket::SELECT_WRITE);
}

mx_err CMx_NonSecureSocket::setBlocking(bool blocking) {
    if (m_sock) {
        m_sock->setBlocking(blocking);
    }
    m_bIsBlocking = blocking;
    return mx_err::ok;
}

mx_err CMx_NonSecureSocket::setTimeoutMs(int recvTimeoutMs, int sendTimeoutMs) {
    try {
        if (m_sock) {
            m_sock->setReceiveTimeout(Timespan(0, recvTimeoutMs * 1000));
            m_sock->setSendTimeout(Timespan(0, sendTimeoutMs * 1000));
        }
        return mx_err::ok;
    } catch (...) { return mx_err::io_error; }
}

mx_err CMx_NonSecureSocket::close() {
    try {
        if (m_sock) { m_sock->close(); m_sock.reset(); }
        if (m_server) { m_server->close(); m_server.reset(); }
        m_bIsConnected = false;
        return mx_err::ok;
    } catch (...) { return mx_err::io_error; }
}

std::string CMx_NonSecureSocket::nowIso8601() {
    Timestamp ts;
    return DateTimeFormatter::format(ts, "%Y-%m-%dT%H:%M:%S.%iZ");
}

std::string CMx_NonSecureSocket::clientId() const {
    if (!m_sock || !m_bIsConnected) return {};
    try {
        return m_sock->peerAddress().toString();
    } catch (...) { return {}; }
}

// ---- High-level receive helpers ----

mx_err CMx_NonSecureSocket::receiveLengthPrefixed(MxMessage& out) {
    out = {};
    uint32_t netLen = 0;
    int got = 0;
    mx_err ec = recvBytes(&netLen, sizeof(netLen), &got);
    if (ec != mx_err::ok) return ec;
    if (got != sizeof(netLen)) return mx_err::io_error;

    // assume network order (big-endian) for the prefix
    uint32_t len = ((netLen & 0xFF) << 24) | ((netLen & 0xFF00) << 8) |
                   ((netLen & 0xFF0000) >> 8) | ((netLen >> 24) & 0xFF);
    if (len == 0) { out.data.clear(); out.clientId = clientId(); out.iso8601Ts = nowIso8601(); return mx_err::ok; }

    out.data.resize(len);
    std::size_t off = 0;
    while (off < len) {
        int chunk = 0;
        ec = recvBytes(out.data.data() + off, static_cast<int>(len - off), &chunk);
        if (ec != mx_err::ok) return ec;
        if (chunk <= 0) return mx_err::disconnected;
        off += static_cast<std::size_t>(chunk);
    }
    out.clientId = clientId();
    out.iso8601Ts = nowIso8601();
    return mx_err::ok;
}

mx_err CMx_NonSecureSocket::receiveDelimiterBased(const std::string& delimiter, MxMessage& out) {
    out = {};
    if (delimiter.empty()) return mx_err::invalid_arg;

    std::string buf;
    buf.reserve(1024);
    char tmp[1024];

    for (;;) {
        int got = 0;
        mx_err ec = recvBytes(tmp, sizeof(tmp), &got);
        if (ec != mx_err::ok) return ec;
        if (got <= 0) return mx_err::disconnected;

        buf.append(tmp, tmp + got);
        auto pos = buf.find(delimiter);
        if (pos != std::string::npos) {
            out.data.assign(buf.data(), pos);
            // keep remainder for your own framing buffer if needed
            out.clientId = clientId();
            out.iso8601Ts = nowIso8601();
            return mx_err::ok;
        }
        // else: keep looping to accumulate
    }
}

mx_err CMx_NonSecureSocket::receiveFixedLength(std::size_t N, MxMessage& out) {
    out = {};
    if (N == 0) { out.clientId = clientId(); out.iso8601Ts = nowIso8601(); return mx_err::ok; }

    out.data.resize(N);
    std::size_t off = 0;
    while (off < N) {
        int got = 0;
        mx_err ec = recvBytes(out.data.data() + off, static_cast<int>(N - off), &got);
        if (ec != mx_err::ok) return ec;
        if (got <= 0) return mx_err::disconnected;
        off += static_cast<std::size_t>(got);
    }
    out.clientId = clientId();
    out.iso8601Ts = nowIso8601();
    return mx_err::ok;
}
