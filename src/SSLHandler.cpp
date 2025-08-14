#include "SSLHandler.h"
#include <Poco/Net/SSLManager.h>
#include <iostream>

SSLHandler::SSLHandler() : session_(nullptr) {
    Poco::Net::initializeSSL();
}

bool SSLHandler::connectToServer(const std::string& host, int port) {
    try {
        host_ = host;
        session_ = new Poco::Net::HTTPSClientSession(host, port);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Connection error: " << e.what() << std::endl;
        return false;
    }
}

std::string SSLHandler::sendRequest(const std::string& path) {
    try {
        Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET, path);
        session_->sendRequest(request);

        Poco::Net::HTTPResponse response;
        std::istream& rs = session_->receiveResponse(response);
        std::string responseStr;
        std::getline(rs, responseStr);
        return responseStr;
    } catch (const std::exception& e) {
        return std::string("Error: ") + e.what();
    }
}

void SSLHandler::testWebsites() {
    // List of websites to test
    std::vector<std::pair<std::string, int>> websites = {
        {"api.github.com", 443},
        {"api.openweathermap.org", 443},
        {"api.exchangerate-api.com", 443}
    };

    for (const auto& site : websites) {
        std::cout << "\nTesting connection to: " << site.first << std::endl;

        if (connectToServer(site.first, site.second)) {
            std::cout << "✓ Successfully connected to " << site.first << std::endl;
            std::string response = sendRequest("/");
            std::cout << "Response: " << response << std::endl;
        } else {
            std::cout << "✗ Failed to connect to " << site.first << std::endl;
        }

        std::cout << "----------------------------------------" << std::endl;
    }
}