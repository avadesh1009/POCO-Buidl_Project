#include "CMx_Non_SecureSocket.h"
#include "SSLHandler.h"
#include <iostream>
#include <thread>
#include <string>
#include <exception>
// ---------------- SSL Test ----------------
void runSSLTests() {
    try {
        SSLHandler handler;
        handler.testWebsites();  // only call one function
    } catch (const std::exception& e) {
        std::cerr << "SSL Test Error: " << e.what() << std::endl;
    }
}
// ---------------- Server ----------------
void runServer(int port, int ipMode)
{
    try {
        CMx_NonSecureSocket server;

        // Create server socket with default reuseAddress/reusePort
        server.createServerSocket(port, (IPMode)ipMode);

        std::cout << "Server listening on port " << port << "\n";

        auto clientSocket = server.accept();
        if (!clientSocket) {
            std::cerr << "Failed to accept client\n";
            return;
        }

        std::cout << "Client connected\n";

        std::string msg;
        while (true) {
            mx_err ec = clientSocket->receiveUntilEOM(msg);
            if (ec != mx_err::ok) {
                std::cerr << "Receive error: " << static_cast<int>(ec) << "\n";
                break;
            }

            std::cout << "Received: " << msg << "\n";

            // Echo back
            clientSocket->sendMessage(msg);

            msg.clear(); // clear for next message
        }

    } catch (const std::exception& e) {
        std::cerr << "Server Exception: " << e.what() << "\n";
    }
}

// ---------------- Client ----------------
void runClient(const std::string& ip, int port)
{
    try {
        CMx_NonSecureSocket client;

        if (!client.connect(ip, port)) {
            std::cerr << "Failed to connect to server " << ip << ":" << port << "\n";
            return;
        }

        std::cout << "Connected to server " << ip << ":" << port << "\n";

        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            if (line.empty()) break;

            client.sendMessage(line + "\n");

            std::string response;
            mx_err ec = client.receiveUntilEOM(response);
            if (ec != mx_err::ok) {
                std::cerr << "Receive error: " << static_cast<int>(ec) << "\n";
                break;
            }

            std::cout << "Echoed: " << response << "\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Client Exception: " << e.what() << "\n";
    }
}

// ---------------- Main ----------------
int main() {
    try {
        std::cout << "Select test mode:\n";
        std::cout << "1. SSL Test\n";
        std::cout << "2. Socket Test (Server/Client)\n";
        std::cout << "Enter choice: ";

        int choice = 0;
        std::cin >> choice;
        std::cin.ignore(); // flush newline

        switch (choice) {
            case 1: { // SSL Test
                runSSLTests();
                break;
            }
            case 2: { // Socket Test
                std::cout << "Select mode:\n";
                std::cout << "1. Server\n";
                std::cout << "2. Client\n";
                std::cout << "Enter choice: ";
                
                int sc = 0;
                std::cin >> sc;
                std::cin.ignore();

                switch (sc) {
                    case 1: { // Server
                        int port = 0;
                        int ipMode = 0;
                        std::cout << "Enter port to listen on: ";
                        std::cin >> port;

                        std::cout << "Enter IP Mode(IPv4=1,IPv6=2,Both=3): ";
                        std::cin >> ipMode;

                        std::cin.ignore();
                        runServer(port,ipMode);
                        break;
                    }
                    case 2: { // Client
                        std::string ip;
                        int port = 0;
                        std::cout << "Enter server IP: ";
                        std::cin >> ip;
                        std::cout << "Enter server port: ";
                        std::cin >> port;
                        std::cin.ignore();
                        runClient(ip, port);
                        break;
                    }
                    default:
                        std::cerr << "Invalid socket mode choice\n";
                        return 1;
                }
                break;
            }
            default:
                std::cerr << "Invalid test mode choice\n";
                return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
