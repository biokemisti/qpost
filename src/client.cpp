#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include "handshake.hpp"

int main(int argc, char *argv[])
{
    int send_socket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(12345);

    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    connect(send_socket, (sockaddr *)&address, sizeof(address));

    handshake::client_handshake(send_socket);

    close(send_socket);

    return 0;
}

// qpost <destination ip> <local file path> <remote file path>
// -a --algorithm <hybrid//kyber/x25519>
// -h --help