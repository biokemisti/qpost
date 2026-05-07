#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include "handshake.hpp"

struct Arguments
{
    int port_number;
    std::string ip_address;
    std::string local_file_path;
    std::string remote_file_path;
};

int run_client(int argc, char *argv[]);
int run_server(int argc, char *argv[]);
int run_set_pre_shared_key(int argc, char *argv[]);
void load_pre_shared_key(uint8_t *pre_shared_key);
void create_config_directory();
void save_pre_shared_key(const std::string &pre_shared_key_hex);
std::string get_config_path();
Arguments parse_arguments(const std::string &mode, int argc, char *argv[]);
int run_help();

int main(int argc, char *argv[])
{
    try
    {
        if (argc < 2)
        {
            throw std::invalid_argument("Invalid number of arguments.");
        }

        const std::string operation_mode = argv[1];

        if (operation_mode == "client")
            return run_client(argc, argv);

        else if (operation_mode == "server")
            return run_server(argc, argv);

        else if (operation_mode == "set-psk")
            return run_set_pre_shared_key(argc, argv);

        else if (operation_mode == "--help")
            return run_help();

        else
        {
            throw std::invalid_argument("Invalid command.");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n"
                  << "Type --help for more information." << "\n";
        return 1;
    }

    return 0;
}

int run_client(int argc, char *argv[])
{
    Arguments arguments = parse_arguments("client", argc, argv);

    int send_socket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(arguments.port_number);

    if (inet_pton(AF_INET, arguments.ip_address.c_str(), &address.sin_addr) <= 0)
    {
        throw std::runtime_error("Invalid IP address.");
    }

    if (connect(send_socket, (sockaddr *)&address, sizeof(address)) < 0)
    {
        throw std::runtime_error("Connection failed.");
    }

    uint8_t pre_shared_key[handshake::config::PRE_SHARED_KEY_SIZE];
    load_pre_shared_key(pre_shared_key);

    handshake::client_handshake(send_socket, pre_shared_key);

    close(send_socket);
    return 0;
}

int run_server(int argc, char *argv[])
{
    Arguments arguments = parse_arguments("server", argc, argv);

    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(arguments.port_number);

    bind(listen_socket, (sockaddr *)&address, sizeof(address));

    listen(listen_socket, 1);
    std::cout << "Listening on port " << arguments.port_number << ".\n";

    int client = accept(listen_socket, nullptr, nullptr);

    uint8_t pre_shared_key[handshake::config::PRE_SHARED_KEY_SIZE];
    load_pre_shared_key(pre_shared_key);

    handshake::server_handshake(client, pre_shared_key);

    close(client);
    close(listen_socket);
    return 0;
}

int run_set_pre_shared_key(int argc, char *argv[])
{
    if (argc != 3 && argc != 4)
    {
        throw std::invalid_argument("Invalid number of arguments.");
    }

    std::string pre_shared_key_hex;

    const std::string arg = argv[2];
    if (arg == "--file")
    {
        std::ifstream file(argv[3]);
        if (!file)
        {
            throw std::runtime_error("Failed to open PSK file.");
        }
        std::getline(file, pre_shared_key_hex);
    }
    else
    {
        pre_shared_key_hex = argv[2];
    }

    save_pre_shared_key(pre_shared_key_hex);
    return 0;
}

void load_pre_shared_key(uint8_t *pre_shared_key)
{
    std::ifstream file(get_config_path());
    if (!file)
    {
        throw std::runtime_error("PSK not configured.");
    }

    std::string line;
    std::getline(file, line);
    const std::string prefix = "psk=";
    if (line.rfind(prefix, 0) != 0)
    {
        throw std::runtime_error("Invalid configuration format.");
    }
    std::string hex = line.substr(prefix.size());
    if (hex.size() != handshake::config::PRE_SHARED_KEY_SIZE * 2)
    {
        throw std::runtime_error("Invalid PSK length");
    }
    for (size_t i = 0; i < handshake::config::PRE_SHARED_KEY_SIZE; i++)
    {
        std::string byte_str = hex.substr(i * 2, 2);
        pre_shared_key[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
    }
}

void create_config_directory()
{
    const char *home_directory = std::getenv("HOME");
    if (!home_directory)
        throw std::runtime_error("Home directory not set.");

    std::filesystem::create_directories(
        std::string(home_directory) + "/.config/qpost");
}

void save_pre_shared_key(const std::string &pre_shared_key_hex)
{
    if (pre_shared_key_hex.size() != handshake::config::PRE_SHARED_KEY_SIZE * 2)
    {
        throw std::invalid_argument("Invalid PSK.");
    }

    create_config_directory();

    std::ofstream file(get_config_path(), std::ios::trunc);
    if (!file)
        throw std::runtime_error("Failed to create config file.");

    file << "psk=" << pre_shared_key_hex << "\n";
}

std::string get_config_path()
{
    const char *home = std::getenv("HOME");
    if (!home)
    {
        throw std::runtime_error("Failed to get config path.");
    }
    return std::string(home) + "/.config/qpost/config";
}

Arguments parse_arguments(const std::string &mode, int argc, char *argv[])
{
    Arguments arguments;

    if (argc < 3)
    {
        throw std::invalid_argument("Missing port number.");
    }

    try
    {
        arguments.port_number = std::stoi(argv[2]);
    }
    catch (...)
    {
        throw std::invalid_argument("Invalid port number.");
    }

    if (mode == "server")
    {
        if (argc != 3)
            throw std::invalid_argument("Invalid number of arguments.");

        return arguments;
    }

    else if (mode == "client")
    {
        if (argc != 6)
        {
            throw std::invalid_argument("Invalid number of arguments.");
        }

        arguments.ip_address = argv[3];
        arguments.local_file_path = argv[4];
        arguments.remote_file_path = argv[5];
    }

    else
    {
        throw std::invalid_argument("An unknown error happened.");
    }

    return arguments;
}

int run_help()
{
    const char *logo =
        "\n"
        "                                       █████       \n"
        "                                      ▒▒███        \n"
        "  ████████ ████████   ██████   █████  ███████      \n"
        " ███▒▒███ ▒▒███▒▒███ ███▒▒███ ███▒▒  ▒▒▒███▒       \n"
        "▒███ ▒███  ▒███ ▒███▒███ ▒███▒▒█████   ▒███        \n"
        "▒███ ▒███  ▒███ ▒███▒███ ▒███ ▒▒▒▒███  ▒███ ███    \n"
        "▒▒███████  ▒███████ ▒▒██████  ██████   ▒▒█████     \n"
        " ▒▒▒▒▒███  ▒███▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒▒▒     ▒▒▒▒▒      \n"
        "     ▒███  ▒███                                    \n"
        "     █████ █████                                   \n"
        "    ▒▒▒▒▒ ▒▒▒▒▒                                    \n"
        "\n";

    const char *instructions =
        "client    <port number> <ip address> <local file path> <remote file path>\n"
        "server    <port number>\n"
        "set-psk   <pre shared key> | --file <file path>\n";

    std::cout << logo;
    std::cout << instructions;

    return 0;
}

// Future fixes:
// help message
// error handling to syscall returns
// close sockets on failure
// validate PSK
// better error messages
