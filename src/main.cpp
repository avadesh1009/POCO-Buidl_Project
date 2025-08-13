#include "SSLHandler.h"
#include <iostream>
#include <vector>
#include <utility>

int main() {
    try {
        SSLHandler handler;
        
        // Define multiple websites to test
        std::vector<std::pair<std::string, int>> websites = {
            {"api.github.com", 443},
            {"api.openweathermap.org", 443},
            {"api.exchangerate-api.com", 443}
        };

        // Test each website
        for (const auto& site : websites) {
            std::cout << "\nTesting connection to: " << site.first << std::endl;
            
            if (handler.connectToServer(site.first, site.second)) {
                std::cout << "✓ Successfully connected to " << site.first << std::endl;
                
                // Send a request
                std::string response = handler.sendRequest("/");
                std::cout << "Response: " << response << std::endl;
            } else {
                std::cout << "✗ Failed to connect to " << site.first << std::endl;
            }
            
            std::cout << "----------------------------------------" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}