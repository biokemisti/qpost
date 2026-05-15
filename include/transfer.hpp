#include "handshake.hpp"

namespace transfer
{
    struct Metadata
    {
        std::string file_name;
        uint64_t file_size;
    };

    bool send_loop(int socket, const void *buffer, size_t length);
    bool receive_loop(int socket, const void *buffer, size_t length);

    void stream_send_file(int socket, handshake::SessionKeys session_keys,
                     const std::string &local_file_path,
                     const std::string &remote_file_path);
    
    void stream_receive_file(int socket_fd, handshake::SessionKeys keys);
}