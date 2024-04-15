#include <homelink_client.h>
#include <homelink_security.h>

#include <cstring>
#include <iostream>
#include <string>

int main() {
    HomeLinkClient client;

    initializeSecurity();
    HomeLinkClient__initialize(&client, "test_client");
    HomeLinkClient__login(&client, "passsssssword7777777");

    std::string line;
    while(std::getline(std::cin, line)) {
        std::cout << line << std::endl;
        if(line == "quit") {
            break;
        }
    }

    HomeLinkClient__logout(&client);
    cleanSecurity();

    return 0;
}