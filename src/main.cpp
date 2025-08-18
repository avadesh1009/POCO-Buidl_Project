#include "Mx_Non_SecureSocket.h"
#include <iostream>
#include <string>
#include <memory>

// ---------------- Server ----------------
void runServer(int port, eIpBindingMode ipMode)
{
    try {
        CMx_NonSecureSocket server;

        // Bind
        eMxErrorCode ec = server.bind(port, ipMode, true, true);
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Server] Failed to bind on port " << port
                      << " (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        // Listen
        ec = server.listen();
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Server] Failed to listen (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        std::cout << "[Server] Listening on port " << port << "...\n";

        // Accept client
        auto clientSocket = server.accept();
        if (!clientSocket) {
            std::cerr << "[Server] Failed to accept client\n";
            return;
        }

        std::cout << "[Server] Client connected\n";

        // Echo loop
        std::string msg;
        while (true) {
            msg.clear();
            eMxErrorCode rc = clientSocket->receiveUntilEOM(msg);
            if (rc != eMxErrorCode::NO_ERR) {
                std::cerr << "[Server] Receive failed (err=" << static_cast<int>(rc) << ")\n";
                break;
            }

            std::cout << "[Server] Received: " << msg << "\n";

            rc = clientSocket->sendMessage(msg);
            if (rc != eMxErrorCode::NO_ERR) {
                std::cerr << "[Server] Send failed (err=" << static_cast<int>(rc) << ")\n";
                break;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "[Server Exception] " << e.what() << "\n";
    }
}

// ---------------- Client ----------------
void runClient(const std::string& ip, int port)
{
    try {
        CMx_NonSecureSocket client;

        eMxErrorCode ec = client.connect(ip, port, 5);
        if (ec != eMxErrorCode::NO_ERR) {
            std::cerr << "[Client] Failed to connect to "
                      << ip << ":" << port << " (err=" << static_cast<int>(ec) << ")\n";
            return;
        }

        std::cout << "[Client] Connected to " << ip << ":" << port << "\n";

        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            if (line.empty()) break;

            // Append EOM marker
            line.push_back(EOM);

            ec = client.sendMessage(line);
            if (ec != eMxErrorCode::NO_ERR) {
                std::cerr << "[Client] Send failed (err=" << static_cast<int>(ec) << ")\n";
                break;
            }

            std::string response;
            ec = client.receiveUntilEOM(response);
            if (ec != eMxErrorCode::NO_ERR) {
                std::cerr << "[Client] Receive failed (err=" << static_cast<int>(ec) << ")\n";
                break;
            }

            std::cout << "[Client] Echoed: " << response << "\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "[Client Exception] " << e.what() << "\n";
    }
}

// ---------------- Main ----------------
int main()
{

Continues:
    try {

        std::cout << "Select mode:\n"
                  << "1. Server\n"
                  << "2. Client\n"
                  << "Choice: ";

        int sc = 0;
        std::cin >> sc;
        std::cin.ignore();

        if (sc == 1) {
            int port, ipMode;
            std::cout << "Enter port to listen on: ";
            std::cin >> port;
            std::cout << "Enter IP Mode (1=IPv4, 2=IPv6, 3=DualStack): ";
            std::cin >> ipMode;
            std::cin.ignore();

            runServer(port, static_cast<eIpBindingMode>(ipMode));
        }
        else if (sc == 2) {
            std::string ip;
            int port;
            std::cout << "Enter server IP: ";
            std::cin >> ip;
            std::cout << "Enter server port: ";
            std::cin >> port;
            std::cin.ignore();

            runClient(ip, port);
        }
        else {
            std::cerr << "[Error] Invalid choice\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "[Main Exception] " << e.what() << "\n";
        return 1;
    }
    
goto Continues;

    return 0;
}
