#include "CMx_Non_SecureSocket.h"
#include <Poco/Timestamp.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timespan.h>
#include <Poco/Exception.h>
#include <cstring>
#include <iostream>

using namespace Poco;
using namespace Poco::Net;

static inline mx_err mapException(const std::exception* e) {
    // You can refine this mapping if you want more fidelity
    return mx_err::io_error;
}

CMx_NonSecureSocket::CMx_NonSecureSocket() : CMx_BaseSocket(false, false) 
{
    m_server = nullptr;
    m_sock = nullptr;  
}

CMx_NonSecureSocket::CMx_NonSecureSocket(StreamSocket&& sock) : CMx_BaseSocket(false, false)
{
    m_sock = std::make_unique<StreamSocket>(std::move(sock));
    m_bIsConnected = true;
}

CMx_NonSecureSocket::~CMx_NonSecureSocket() 
{ 
    close(); 
}

void CMx_NonSecureSocket::createServerSocket(int port, IPMode ipMode, bool reuseAddress, bool reusePort)
{
    bind(port, ipMode, reuseAddress, reusePort);
    listen();

    std::cout << "Server socket created successfully." << std::endl;
}

void CMx_NonSecureSocket::bind(int port, IPMode ipMode, bool reuseAddress, bool reusePort)
{
    m_server = std::make_unique<ServerSocket>();

    auto bindIPv4 = [&]() {
        SocketAddress addr(IPAddress::IPv4, port);
        m_server->bind(addr, reuseAddress);
        std::cout << "Bound using IPv4 only" << std::endl;
    };

    auto bindIPv6 = [&](bool dualStack) {
        SocketAddress addr(IPAddress::IPv6, port);
        m_server->bind6(addr, reuseAddress, reusePort, !dualStack); // !dualStack = IPv6-only
        std::cout << (dualStack ? "Bound using dual-stack (IPv6+IPv4)" : "Bound using IPv6 only") << std::endl;
    };

    try {
        if (ipMode == IPMode::DualStack) {
            bindIPv6(true);  // prefer dual-stack
        }
        else if (ipMode == IPMode::IPv6) {
            bindIPv6(false); // IPv6 only
        }
        else if (ipMode == IPMode::IPv4) {
            bindIPv4();      // IPv4 only
        }
        else {
            throw Poco::IOException("No supported IP protocol on this system");
        }
        std::cout << "Server listening on port " << port << std::endl;
    }
    catch (NotImplementedException &) {
        std::cerr << "IPv6 support is not implemented on this system." << std::endl;
        throw;
    }
    catch (Poco::Exception& ex) {
        std::cerr << "Failed to bind server socket: " << ex.displayText() << std::endl;
        throw;
    }
    catch (...) {
        std::cerr << "Unknown error occurred while binding server socket." << std::endl;
        throw;
    }
}

// New listening API
void CMx_NonSecureSocket::listen(int backlog)
{
    if (!m_server) 
        return;

    m_server->listen(backlog);
    m_bIsServer = true;

    std::cout << "Server is now listening (backlog = " << backlog << ")" << std::endl;
}

std::unique_ptr<CMx_BaseSocket> CMx_NonSecureSocket::accept() {

    if (!m_server) return nullptr;

    try {

        // Accept client connection
        SocketAddress clientAddr;
        StreamSocket client = m_server->acceptConnection(clientAddr);

        std::cout << "Client connected: " << clientAddr.toString() << std::endl;

        // Wrap the StreamSocket into a new CMx_NonSecureSocket
        auto newClient = std::make_unique<CMx_NonSecureSocket>();
        newClient->m_sock = std::make_unique<StreamSocket>(std::move(client));

        return newClient;

    } catch (const Poco::Exception &ex) {

        std::cerr << "Accept failed: " << ex.displayText() << std::endl;
        return nullptr;

    } catch (...) {

        std::cerr << "Unknown exception in accept()" << std::endl;
        return nullptr;
        
    }
}

bool CMx_NonSecureSocket::connect(const std::string& ip, int port, int timeoutSeconds) 
{
     try {

        if (!m_sock) {
            m_sock = std::make_unique<StreamSocket>();
        }

        SocketAddress address(ip, port);
        Poco::Timespan timeout(timeoutSeconds, 0);

        m_sock->connect(address, timeout);

        std::cout << "Connected to " << address.toString()
                  << " with timeout " << timeoutSeconds << "s" << std::endl;
        
        m_bIsConnected = true;

        return true;
    }
    catch (Poco::Exception& ex) {
        std::cerr << "Connection failed: " << ex.displayText() << std::endl;
        return false;
    }
}

mx_err CMx_NonSecureSocket::send(const char* buf, int len) {

    if (!m_sock) return mx_err::not_ready;

    try {
        int n = m_sock->sendBytes(buf, len);

        // n could be less than len in case of partial send
        if (n == 0) {
            return mx_err::would_block;  // nothing sent
        }
        return mx_err::ok;
    } 
    catch (const Poco::TimeoutException&) {
        return mx_err::timeout;
    } 
    catch (const Poco::IOException&) {
        return mx_err::io_error;
    }
    catch (const std::exception& e) {
        return mapException(&e);  // your existing mapper
    }
}

mx_err CMx_NonSecureSocket::sendMessage(const std::string& msg) {
    if (msg.empty()) return mx_err::invalid_arg;

    // Send the message length first
    uint32_t netLen = htonl(static_cast<uint32_t>(msg.size()));
    mx_err ec = send(reinterpret_cast<const char*>(&netLen), sizeof(netLen));
    if (ec != mx_err::ok) return ec;

    // Now send the actual message
    return send(msg.data(), static_cast<int>(msg.size()));
}

mx_err CMx_NonSecureSocket::receive(char* buf, int maxLen) {
    if (!m_sock) return mx_err::not_ready;
    try {
        int n = m_sock->receiveBytes(buf, maxLen);
       
        if (n == 0) return mx_err::disconnected;

        return mx_err::ok;
        
    } catch (const TimeoutException&) {
        return mx_err::timeout;
    } catch (const std::exception& e) {
        return mapException(&e);
    }
}

mx_err CMx_NonSecureSocket::receiveUntilEOM(std::string& msg) {
    if (!m_sock) return mx_err::not_ready;

    try {
        char buf[1024];
        int totalReceived = 0;

        while (true) {
            int n = m_sock->receiveBytes(buf, sizeof(buf));
            if (n <= 0) {
                if (n == 0) return mx_err::disconnected; // socket closed
                return mx_err::io_error; // error occurred
            }

            totalReceived += n;
            msg.append(buf, n);

            // Check for end of message condition
            if (msg.find("\r\n") != std::string::npos || msg.find("\n") != std::string::npos) {
                break; // EOM found
            }
        }

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

mx_err CMx_NonSecureSocket::setTimeoutMs(int TimeoutMs) {
    try {
        if (m_sock) {
            m_sock->setReceiveTimeout(Timespan(0, TimeoutMs * 1000));
            m_sock->setSendTimeout(Timespan(0, TimeoutMs * 1000));
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
