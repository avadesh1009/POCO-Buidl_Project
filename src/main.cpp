#include "Mx_Non_SecureSocket.h"
#include "Mx_SecureSocket.h"
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <vector>
#include <mutex>

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
                std::cerr << "[Server] Client " << clientAddr << " receive failed (err=" << static_cast<int>(rc) << ")\n";
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

            message += "10";               // Third field
            message += FSP;

            message += "16";               // Fourth field
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
                std::cerr << "[Server] Client " << clientAddr << " send failed (err=" << static_cast<int>(rc) << ")\n";
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
void runServer(int port, eIpBindingMode ipMode,int isApplySSL)
{
    try {

        std::unique_ptr<CMx_BaseSocket> server;
        if (isApplySSL) {
            server = std::make_unique<CMx_SecureSocket>(true);
        } else {
            server = std::make_unique<CMx_NonSecureSocket>(true);
        }

        eMxErrorCode ec = server->bind(port, ipMode, true, true);
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
void runClient(const std::string& ip, int port,int isApplySSL)
{
    try {
        std::unique_ptr<CMx_BaseSocket> client;
        if (isApplySSL) {
            client = std::make_unique<CMx_SecureSocket>(true);
        } else {
            client = std::make_unique<CMx_NonSecureSocket>(true);
        }

        eMxErrorCode ec = client->connect(ip, port, 5);
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Client] Failed to connect to "
                      << ip << ":" << port << " (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        std::cout << "[Client] Connected to " << ip << ":" << port << "\n";

        client->setBlocking(true);

        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            if (line.empty()) break;

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
            } else {
                line += EOM;
                ec = client->sendMessage(line);
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
        }

        client->close();
        std::cout << "[Client] Disconnected\n";

    } catch (const std::exception& e) {
        std::cerr << "[Client Exception] " << e.what() << "\n";
    }
}

// ---------------- Main ----------------
int main()
{
    while (true) {
        try {
            std::cout << "\nSelect mode:\n"
                      << "1. Server\n"
                      << "2. Client\n"
                      << "0. Exit\n"
                      << "Choice: ";

            int sc = 0;
            std::cin >> sc;
            std::cin.ignore();

            if (sc == 1) {
                int port, ipMode,ApplySSl;
                std::cout << "Enter port to listen on: ";
                std::cin >> port;
                std::cout << "Enter IP Mode (1=IPv4, 2=IPv6, 3=DualStack): ";
                std::cin >> ipMode;
                std::cout << "Apply SSL Communication (TRUE = 1, FALSE = 0): ";
                std::cin >> ApplySSl;
                std::cin.ignore();

                runServer(port, static_cast<eIpBindingMode>(ipMode),ApplySSl);
            }
            else if (sc == 2) {
                std::string ip;
                int port;
                int ApplySSl;
                std::cout << "Enter server IP: ";
                std::cin >> ip;
                std::cout << "Enter server port: ";
                std::cin >> port;
                 std::cout << "Apply SSL Communication (TRUE = 1, FALSE = 0): ";
                std::cin >> ApplySSl;
                std::cin.ignore();

                runClient(ip, port,ApplySSl);
            }
            else if (sc == 0) {
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
