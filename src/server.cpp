#include <netinet/in.h>
#include <iostream>
#include <unistd.h>
#include "handshake.hpp"

int main(int argc, char *argv[])
{
    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(12345);

    bind(listen_socket, (sockaddr *)&address, sizeof(address));

    listen(listen_socket, 1);
    std::cout << "Listening on port 666\n";

    int client = accept(listen_socket, nullptr, nullptr);

    handshake::server_handshake(client);

    close(client);
    close(listen_socket);

    return 0;
}