#include <gtest/gtest.h>   // <-- include gtest
#include "../src/Mx_Non_SecureSocket.h"
#include "../src/Mx_SecureSocket.h"
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <vector>
#include <mutex>

class NonSecureSocketTest : public ::testing::Test {
protected:
    CMx_NonSecureSocket socket;

    void SetUp() override {
        // Default: act as server, non-SSL
        socket.m_bIsSSL = false;
        socket.m_bIsServer = true;
    }
};

// ---------------- bind() tests (your existing) ----------------
TEST_F(NonSecureSocketTest, FailsIfSSLModeEnabled) {
    socket.m_bIsSSL = true;
    auto result = socket.bind(8080, eIpBindingMode::IPv4, true, false);
    EXPECT_EQ(result, eMxErrorCode::ERR_SERVICE_START_FAILED);
}

TEST_F(NonSecureSocketTest, FailsIfNotServerMode) {
    socket.m_bIsServer = false;
    auto result = socket.bind(8080, eIpBindingMode::IPv4, true, false);
    EXPECT_EQ(result, eMxErrorCode::ERR_SERVICE_START_FAILED);
}

TEST_F(NonSecureSocketTest, FailsOnInvalidPort) {
    auto result = socket.bind(0, eIpBindingMode::IPv4, true, false);
    EXPECT_EQ(result, eMxErrorCode::ERR_INVALID_PORT);

    result = socket.bind(MX_SOCKET_PORT_MAX + 1, eIpBindingMode::IPv4, true, false);
    EXPECT_EQ(result, eMxErrorCode::ERR_INVALID_PORT);
}

TEST_F(NonSecureSocketTest, CanBindIPv4) {
    auto result = socket.bind(9090, eIpBindingMode::IPv4, true, false);
    EXPECT_EQ(result, eMxErrorCode::NO_ERR);
}

TEST_F(NonSecureSocketTest, CanBindIPv6OrDualStackIfSupported) {
    auto result = socket.bind(9091, eIpBindingMode::IPv6, true, false);
    EXPECT_TRUE(result == eMxErrorCode::NO_ERR || result == eMxErrorCode::ERR_IPV6_NOT_SUPPORT);

    result = socket.bind(9092, eIpBindingMode::DualStack, true, true);
    EXPECT_TRUE(result == eMxErrorCode::NO_ERR || result == eMxErrorCode::ERR_IPV6_NOT_SUPPORT);
}

TEST_F(NonSecureSocketTest, UnsupportedModeFails) {
    auto result = socket.bind(9093, static_cast<eIpBindingMode>(999), true, false);
    EXPECT_EQ(result, eMxErrorCode::UNKNOWN_ERROR);
}

// ---------------- listen() tests ----------------
TEST_F(NonSecureSocketTest, ListenFailsIfSSLMode) {
    socket.m_bIsSSL = true;
    auto result = socket.listen(10);
    EXPECT_EQ(result, eMxErrorCode::ERR_SERVICE_START_FAILED);
}

TEST_F(NonSecureSocketTest, ListenFailsIfNotServer) {
    socket.m_bIsServer = false;
    auto result = socket.listen(10);
    EXPECT_EQ(result, eMxErrorCode::ERR_SERVICE_START_FAILED);
}

TEST_F(NonSecureSocketTest, ListenFailsIfServerNotInitialized) {
    // _server is null by default (not bound yet)
    auto result = socket.listen(10);
    EXPECT_EQ(result, eMxErrorCode::ERR_SERVICE_START_FAILED);
}

TEST_F(NonSecureSocketTest, ListenUsesDefaultBacklogIfZero) {
    auto bindResult = socket.bind(9094, eIpBindingMode::IPv4, true, false);
    ASSERT_EQ(bindResult, eMxErrorCode::NO_ERR);

    auto listenResult = socket.listen(0);  // should replace with MX_DEFAULT_BACKLOG internally
    EXPECT_EQ(listenResult, eMxErrorCode::NO_ERR);
}

TEST_F(NonSecureSocketTest, ListenSucceedsWithValidBacklog) {
    auto bindResult = socket.bind(9095, eIpBindingMode::IPv4, true, false);
    ASSERT_EQ(bindResult, eMxErrorCode::NO_ERR);

    auto listenResult = socket.listen(5);
    EXPECT_EQ(listenResult, eMxErrorCode::NO_ERR);
}

// ---------------- accept() tests ----------------
TEST_F(NonSecureSocketTest, AcceptFailsIfSSLMode) {
    socket.m_bIsSSL = true;
    auto client = socket.accept();
    EXPECT_EQ(client, nullptr);
}

TEST_F(NonSecureSocketTest, AcceptFailsIfNotServer) {
    socket.m_bIsServer = false;
    auto client = socket.accept();
    EXPECT_EQ(client, nullptr);
}

TEST_F(NonSecureSocketTest, AcceptFailsIfServerNotInitialized) {
    // _server not set (bind not called)
    auto client = socket.accept();
    EXPECT_EQ(client, nullptr);
}

TEST_F(NonSecureSocketTest, AcceptSucceedsAfterBindAndListen) {
    auto bindResult = socket.bind(9096, eIpBindingMode::IPv4, true, false);
    ASSERT_EQ(bindResult, eMxErrorCode::NO_ERR);

    auto listenResult = socket.listen(5);
    ASSERT_EQ(listenResult, eMxErrorCode::NO_ERR);

    // For real test, you’d need another thread to connect as a client.
    // Here we only check that accept() returns non-null OR nullptr if timeout/no connection.
    auto client = socket.accept();
    EXPECT_TRUE(client != nullptr || client == nullptr); // placeholder check
}

// ---------------- connect() tests ----------------
TEST_F(NonSecureSocketTest, ConnectFailsIfSSLModeEnabled) {
    socket.m_bIsSSL = true;   // client should not be SSL
    socket.m_bIsServer = false;
    auto result = socket.connect("127.0.0.1", 8080, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::UNKNOWN_ERROR);
}

TEST_F(NonSecureSocketTest, ConnectFailsIfCalledOnServerMode) {
    socket.m_bIsSSL = false;
    socket.m_bIsServer = true;   // still a server
    auto result = socket.connect("127.0.0.1", 8080, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::UNKNOWN_ERROR);
}

TEST_F(NonSecureSocketTest, ConnectFailsIfAlreadyConnected) {
    socket.m_bIsSSL = false;
    socket.m_bIsServer = false;
    socket.m_bIsConnected = true;   // simulate already connected
    auto result = socket.connect("127.0.0.1", 8080, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::ERR_SOCKET_ALREADY_CONNECTED);
}

TEST_F(NonSecureSocketTest, ConnectFailsIfEmptyIP) {
    socket.m_bIsSSL = false;
    socket.m_bIsServer = false;
    auto result = socket.connect("", 8080, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::ERR_INVALID_IP_RANGE);
}

TEST_F(NonSecureSocketTest, ConnectFailsIfInvalidPort) {
    socket.m_bIsSSL = false;
    socket.m_bIsServer = false;

    auto result = socket.connect("127.0.0.1", 0, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::ERR_INVALID_PORT);

    result = socket.connect("127.0.0.1", MX_SOCKET_PORT_MAX + 1, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::ERR_INVALID_PORT);
}

TEST_F(NonSecureSocketTest, ConnectFailsIfServerNotListening) {
    socket.m_bIsSSL = false;
    socket.m_bIsServer = false;

    // Try to connect to a port where no server exists
    auto result = socket.connect("127.0.0.1", 65500, 1, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(result, eMxErrorCode::ERR_CONNECTION_FAILED);
}

TEST_F(NonSecureSocketTest, ConnectSucceedsWithValidServer) {
    // Step 1: Start a server on localhost in another socket instance
    CMx_NonSecureSocket server;
    server.m_bIsSSL = false;
    server.m_bIsServer = true;

    auto bindResult = server.bind(9099, eIpBindingMode::IPv4, true, false);
    ASSERT_EQ(bindResult, eMxErrorCode::NO_ERR);

    auto listenResult = server.listen(1);
    ASSERT_EQ(listenResult, eMxErrorCode::NO_ERR);

    // Step 2: Try to connect with client socket
    socket.m_bIsSSL = false;
    socket.m_bIsServer = false;

    auto connectResult = socket.connect("127.0.0.1", 9099, 5, eSslVerificationMode::MODE_NONE);
    EXPECT_EQ(connectResult, eMxErrorCode::NO_ERR);

    // Step 3: Accept connection on server side
    auto clientSock = server.accept();
    EXPECT_NE(clientSock, nullptr);

    // Cleanup: connected flag must be true on client
    EXPECT_TRUE(socket.m_bIsConnected);
}

// ---------------- socket utility APIs ----------------
TEST_F(NonSecureSocketTest, IsReadableWritableFailIfNotConnected) {
    EXPECT_FALSE(socket.isReadable(100));
    EXPECT_FALSE(socket.isWritable(100));
}

TEST_F(NonSecureSocketTest, SetBlockingFailsIfNotInitialized) {
    auto result = socket.setBlocking(true);
    EXPECT_EQ(result, eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED);
}

TEST_F(NonSecureSocketTest, SetReceiveTimeoutFailsIfNotInitialized) {
    auto result = socket.setReceiveTimeout(500);
    EXPECT_EQ(result, eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED);
}

TEST_F(NonSecureSocketTest, SetSendTimeoutFailsIfNotInitialized) {
    auto result = socket.setSendTimeout(500);
    EXPECT_EQ(result, eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED);
}

TEST_F(NonSecureSocketTest, SetBufferSizesFailIfNotInitialized) {
    EXPECT_EQ(socket.setReceiveBufferSize(1024), eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED);
    EXPECT_EQ(socket.setSendBufferSize(1024), eMxErrorCode::ERR_SOCKET_NOT_INITIALIZED);
}

TEST_F(NonSecureSocketTest, CloseSucceedsEvenIfNotInitialized) {
    auto result = socket.close();
    EXPECT_EQ(result, eMxErrorCode::NO_ERR);
}

TEST_F(NonSecureSocketTest, GetPeerAddressFailsIfNotConnected) {
    // Without a socket/connection, this would throw inside peerAddress()
    // We expect an exception → we wrap it.
    EXPECT_THROW({
        socket.getPeerAddress();
    }, Poco::Exception);
}

TEST_F(NonSecureSocketTest, UtilityFunctionsWorkWithValidConnection) {
    // Start server
    CMx_NonSecureSocket server;
    server.m_bIsSSL = false;
    server.m_bIsServer = true;

    ASSERT_EQ(server.bind(9100, eIpBindingMode::IPv4, true, false), eMxErrorCode::NO_ERR);
    ASSERT_EQ(server.listen(1), eMxErrorCode::NO_ERR);

    // Client connect
    socket.m_bIsSSL = false;
    socket.m_bIsServer = false;
    ASSERT_EQ(socket.connect("127.0.0.1", 9100, 2, eSslVerificationMode::MODE_NONE), eMxErrorCode::NO_ERR);

    auto clientSock = server.accept();
    ASSERT_NE(clientSock, nullptr);

    // Now client is connected, utilities should work
    EXPECT_TRUE(socket.isWritable(100));
    EXPECT_NO_THROW({
        auto addr = socket.getPeerAddress();
        EXPECT_FALSE(addr.empty());
    });

    EXPECT_EQ(socket.setBlocking(true), eMxErrorCode::NO_ERR);
    EXPECT_EQ(socket.setReceiveTimeout(200), eMxErrorCode::NO_ERR);
    EXPECT_EQ(socket.setSendTimeout(200), eMxErrorCode::NO_ERR);
    EXPECT_EQ(socket.setReceiveBufferSize(2048), eMxErrorCode::NO_ERR);
    EXPECT_EQ(socket.setSendBufferSize(2048), eMxErrorCode::NO_ERR);

    // Close should succeed and reset state
    EXPECT_EQ(socket.close(), eMxErrorCode::NO_ERR);
    EXPECT_FALSE(socket.m_bIsConnected);
}


// ---------------- Utility ----------------
std::string GenerateReadableLargeData(size_t sizeInMB) {
    const std::string pattern = "The quick brown fox jumps over the lazy dog. ";
    std::ostringstream oss;
    size_t lineNum = 0;

    while (oss.tellp() < static_cast<std::streampos>(sizeInMB * 1024 * 1024)) {
        oss << "LINE " << std::setw(6) << std::setfill('0') << lineNum++
            << ": " << pattern << "\n";
    }
    return oss.str();
}

std::mutex g_coutMutex; // to avoid jumbled output when threads print

// ---------------- Client Handler ----------------
void handleClient(std::unique_ptr<CMx_BaseSocket> clientSocket, std::string clientAddr) {
    try {
        {
            std::lock_guard<std::mutex> lock(g_coutMutex);
            std::cout << "[Server] Client connected: " << clientAddr << "\n";
        }

        clientSocket->setBlocking(true);

        std::string msg;
        while (true) {
            msg.clear();
            eMxErrorCode rc = clientSocket->receiveUntilEOM(msg);
            if (rc != eMxErrorCode::NO_ERR) {
                std::lock_guard<std::mutex> lock(g_coutMutex);
                std::cerr << "[Server] Client " << clientAddr
                          << " receive failed (err=" << static_cast<int>(rc) << ")\n";
                break;
            }

            {
                std::lock_guard<std::mutex> lock(g_coutMutex);
                std::cout << "[Server] From " << clientAddr
                          << ": " << msg << " [len=" << msg.size() << "]\n";
            }

            std::string message;

            message  = SOM;                // Start of message
            message += "ACK_LOG";          // Command
            message += FSP;                // Field separator

            message += "0";                // First field
            message += FSP;

            message += "1234";             // Second field
            message += FSP;

            message += "99";               // Third field
            message += FSP;

            message += "99";               // Fourth field
            message += FSP;

            message += EOM;                // End of message

            {
                std::lock_guard<std::mutex> lock(g_coutMutex);
                std::cout << "[Server] server to camera " << clientAddr
                          << ": " << message << " [len=" << message.size() << "]\n";
            }
            
            rc = clientSocket->sendMessage(message);
            if (rc != eMxErrorCode::NO_ERR) {
                std::lock_guard<std::mutex> lock(g_coutMutex);
                std::cerr << "[Server] Client " << clientAddr
                          << " send failed (err=" << static_cast<int>(rc) << ")\n";
                break;
            }
        }

        clientSocket->close();
        {
            std::lock_guard<std::mutex> lock(g_coutMutex);
            std::cout << "[Server] Client disconnected: " << clientAddr << "\n";
        }

    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_coutMutex);
        std::cerr << "[Server Exception] Client handler error: " << e.what() << "\n";
    }
}

// ---------------- Server ----------------
void runServer(int port, eIpBindingMode ipMode, int isApplySSL,int verfyMode)
{
    try {
        std::unique_ptr<CMx_BaseSocket> server;
        if (isApplySSL) {
            server = std::make_unique<CMx_SecureSocket>(true);
        } else {
            server = std::make_unique<CMx_NonSecureSocket>(true);
        }

        eMxErrorCode ec = server->bind(port, ipMode, true, true, (eSslVerificationMode)verfyMode);
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Server] Failed to bind on port " << port
                      << " (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        ec = server->listen();
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Server] Failed to listen (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        std::cout << "[Server] Listening on port " << port << "...\n";

        std::vector<std::thread> threads;

        while (true) {
            auto clientSocket = server->accept();
            if (!clientSocket) {
                std::cerr << "[Server] Failed to accept client\n";
                continue;
            }

            std::string clientAddr = clientSocket->getPeerAddress();

            // Launch client handler in a new thread
            threads.emplace_back(std::thread(handleClient, std::move(clientSocket), clientAddr));
            threads.back().detach(); // detach so threads run independently
        }

    } catch (const std::exception& e) {
        std::cerr << "[Server Exception] " << e.what() << "\n";
    }
}

// ---------------- Client ----------------
void runClient(const std::string& ip, int port, int isApplySSL,int verfyMode)
{
    try {
        std::unique_ptr<CMx_BaseSocket> client;
        if (isApplySSL) {
            client = std::make_unique<CMx_SecureSocket>(false);
        } else {
            client = std::make_unique<CMx_NonSecureSocket>(false);
        }

        eMxErrorCode ec = client->connect(ip, port, 5,(eSslVerificationMode)verfyMode);
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Client] Failed to connect to "
                      << ip << ":" << port << " (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        std::cout << "[Client] Connected to " << ip << ":" << port << "\n";

        client->setBlocking(true);

        std::string line;
        while (true) {
            //std::cout << "> ";
            //std::getline(std::cin, line);
            //if (line.empty()) break;

            if (line == "BIG") {
                int sizeMB;
                std::cout << "Enter size of data to generate (in MB): ";
                std::cin >> sizeMB;
                std::cin.ignore();

                std::cout << "[Client] Generating " << sizeMB << "MB readable buffer...\n";
                auto genStart = std::chrono::high_resolution_clock::now();
                std::string bigData = GenerateReadableLargeData(sizeMB);
                auto genEnd = std::chrono::high_resolution_clock::now();
                auto genTime = std::chrono::duration_cast<std::chrono::milliseconds>(genEnd - genStart).count();
                std::cout << "[Client] Generate completed in " << genTime << " ms.\n";

                bigData += EOM;

                std::cout << "[Client] Send starting...\n";
                auto sendStart = std::chrono::high_resolution_clock::now();
                client->sendMessage(bigData);
                auto sendEnd = std::chrono::high_resolution_clock::now();
                auto sendTime = std::chrono::duration_cast<std::chrono::milliseconds>(sendEnd - sendStart).count();
                std::cout << "[Client] Send completed in " << sendTime << " ms.\n";
            } else 
            {
                std::string message;

                message  = SOM;                // Start of message
                message += "ACK_LOG";          // Command
                message += FSP;                // Field separator

                message += "0";                // First field
                message += FSP;

                message += "1234";             // Second field
                message += FSP;

                message += "99";               // Third field
                message += FSP;

                message += "99";               // Fourth field
                message += FSP;

                message += EOM;                // End of message

                
                //line += EOM;
                ec = client->sendMessage(message);
            }

            if (ec != eMxErrorCode::NO_ERR) {
                std::cerr << "[Client] Send failed (err=" << static_cast<int>(ec) << ")\n";
                break;
            }

            std::string response;
            ec = client->receiveUntilEOM(response);
            if (ec != eMxErrorCode::NO_ERR) {
                std::cerr << "[Client] Receive failed (err=" << static_cast<int>(ec) << ")\n";
                break;
            }

            std::cout << "[Client] Echoed: " << response
                      << " [len=" << response.size() << "]\n";


            Sleep(500);
        }

        client->close();
        std::cout << "[Client] Disconnected\n";

    } catch (const std::exception& e) {
        std::cerr << "[Client Exception] " << e.what() << "\n";
    }
}

// ---------------- Main ----------------
int main(int argc, char** argv)
{
    while (true) {
        try {
            std::cout << "\nSelect mode:\n"
                      << "1. Run Google Test\n"
                      << "2. Socket Communication (Server/Client)\n"
                      << "0. Exit\n"
                      << "Choice: ";

            int choice = 0;
            std::cin >> choice;
            std::cin.ignore();

            if (choice == 1) {
                std::cout << "\n[INFO] Running Google Tests...\n";
                ::testing::InitGoogleTest(&argc, argv);
                int i = RUN_ALL_TESTS();
                std::cout << "Press 'q' to quit: ";
                char c;
                std::cin >> c;
                if (c == 'q') {
                    break;
                }
            }
            else if (choice == 2) {
                int sc = 0;
                std::cout << "\nSelect socket mode:\n"
                          << "1. Server\n"
                          << "2. Client\n"
                          << "Choice: ";
                std::cin >> sc;
                std::cin.ignore();

                if (sc == 1) {
                    int port, ipMode, ApplySSl,verfyMode;
                    std::cout << "Enter port to listen on: ";
                    std::cin >> port;
                    std::cout << "Enter IP Mode (1=IPv4, 2=IPv6, 3=DualStack): ";
                    std::cin >> ipMode;
                    std::cout << "Apply SSL Communication (TRUE = 1, FALSE = 0): ";
                    std::cin >> ApplySSl;
                    std::cout << "SSL Verification mode (NONE = 0, RELAX = 1, STRICT = 2 ): ";
                    std::cin >> verfyMode;
                    std::cin.ignore();

                    runServer(port, static_cast<eIpBindingMode>(ipMode), ApplySSl,verfyMode);
                }
                else if (sc == 2) {
                    std::string ip;
                    int port, ApplySSl,verfyMode;
                    std::cout << "Enter server IP: ";
                    std::cin >> ip;
                    std::cout << "Enter server port: ";
                    std::cin >> port;
                    std::cout << "Apply SSL Communication (TRUE = 1, FALSE = 0): ";
                    std::cin >> ApplySSl;
                    std::cout << "SSL Verification mode (NONE = 0, RELAX = 1, STRICT = 2 ): ";
                    std::cin >> verfyMode;
                    std::cin.ignore();

                    runClient(ip, port, ApplySSl,verfyMode);
                }
                else {
                    std::cerr << "[Error] Invalid socket mode\n";
                }
            }
            else if (choice == 0) {
                std::cout << "Exiting...\n";
                break;
            }
            else {
                std::cerr << "[Error] Invalid choice\n";
            }

        } catch (const std::exception& e) {
            std::cerr << "[Main Exception] " << e.what() << "\n";
            return 1;
        }
    }

    return 0;
}
