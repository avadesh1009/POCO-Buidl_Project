#pragma once
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <string>

class SSLHandler {
public:
    SSLHandler();
    bool connectToServer(const std::string& host, int port);
    std::string sendRequest(const std::string& path);

    void testWebsites();

private:
    std::string host_;
    Poco::Net::HTTPSClientSession* session_;
};