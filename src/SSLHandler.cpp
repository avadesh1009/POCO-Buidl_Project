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