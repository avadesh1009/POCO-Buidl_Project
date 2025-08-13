#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/StreamCopier.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Net/AcceptCertificateHandler.h>
#include <Poco/Net/Context.h>
#include <iostream>
#include <memory>

using namespace Poco::Net;
using namespace Poco;
using namespace std;

int main() {
    try {
        // Initialize SSL
        SharedPtr<InvalidCertificateHandler> certHandler = new AcceptCertificateHandler(false);
        Context::Ptr context = new Context(Context::CLIENT_USE, "", Context::VERIFY_NONE);
        SSLManager::instance().initializeClient(0, certHandler, context);

        // Connect to example.com over HTTPS
        HTTPSClientSession session("www.example.com", 443);
        HTTPRequest request(HTTPRequest::HTTP_GET, "/");
        session.sendRequest(request);

        // Get the response
        HTTPResponse response;
        istream& rs = session.receiveResponse(response);

        cout << "HTTP Response: " << response.getStatus() << " " << response.getReason() << endl;
        StreamCopier::copyStream(rs, cout);
    }
    catch (Exception& ex) {
        cerr << "Poco Exception: " << ex.displayText() << endl;
    }
    catch (std::exception& ex) {
        cerr << "Std Exception: " << ex.what() << endl;
    }
}
