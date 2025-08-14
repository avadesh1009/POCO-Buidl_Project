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
void runServer(int port) {
    try {
        CMx_NonSecureSocket server;
        if (server.bind(port) != mx_err::ok) {
            std::cerr << "Failed to bind server on port " << port << "\n";
            return;
        }

        if (server.listen() != mx_err::ok) {
            std::cerr << "Failed to listen\n";
            return;
        }

        std::cout << "Server listening on port " << port << "\n";

        auto clientSocket = server.accept();
        if (!clientSocket) {
            std::cerr << "Failed to accept client\n";
            return;
        }

        std::cout << "Client connected: " << clientSocket->clientId() << "\n";

        MxMessage msg;
        while (true) {
            mx_err ec = clientSocket->receiveDelimiterBased("\n", msg);
            if (ec != mx_err::ok) {
                std::cerr << "Receive error: " << static_cast<int>(ec) << "\n";
                break;
            }

            std::cout << "Received: " << msg.data << " from " << msg.clientId << "\n";

            // Echo back
            clientSocket->sendString(msg.data + "\n");
        }
    } catch (const std::exception& e) {
        std::cerr << "Server Exception: " << e.what() << "\n";
    }
}

// ---------------- Client ----------------
void runClient(const std::string& ip, int port) {
    try {
        CMx_NonSecureSocket client;
        if (client.connect(ip, port) != mx_err::ok) {
            std::cerr << "Failed to connect to server " << ip << ":" << port << "\n";
            return;
        }

        std::cout << "Connected to server " << ip << ":" << port << "\n";

        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            if (line.empty()) break;

            client.sendString(line + "\n");

            MxMessage msg;
            mx_err ec = client.receiveDelimiterBased("\n", msg);
            if (ec != mx_err::ok) {
                std::cerr << "Receive error: " << static_cast<int>(ec) << "\n";
                break;
            }
            std::cout << "Echoed: " << msg.data << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Client Exception: " << e.what() << "\n";
    }
}

// ---------------- Argument Dispatcher ----------------
int runModeFromArgs(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " server <port> | client <ip> <port>\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "server" && argc == 3) {
        int port = std::stoi(argv[2]);
        runServer(port);
    } 
    else if (mode == "client" && argc == 4) {
        std::string ip = argv[2];
        int port = std::stoi(argv[3]);
        runClient(ip, port);
    } 
    else {
        std::cerr << "Invalid arguments\n";
        return 1;
    }

    return 0;
}

// ---------------- Main ----------------
int main(int argc, char* argv[]) {
    
    // Run SSL test first
    //runSSLTests();

    // Run server/client based on command line
    return runModeFromArgs(argc, argv);
}
