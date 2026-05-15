#include <sodium.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <netinet/in.h>
#include <vector>
#include <iostream>
#include "transfer.hpp"
#include "crypto_utils.hpp"

namespace transfer
{
    bool send_loop(int socket, const void *buffer, size_t length)
    {
        const char *ptr = static_cast<const char *>(buffer);
        size_t bytes_sent = 0;
        while (bytes_sent < length)
        {
            ssize_t bytes = send(socket, ptr + bytes_sent, length - bytes_sent, 0);
            if (bytes <= 0)
            {
                return false;
            }
            bytes_sent += bytes;
        }
        return true;
    }

    bool receive_loop(int socket, void *buffer, size_t length)
    {
        char *ptr = static_cast<char *>(buffer);
        size_t bytes_received = 0;
        while (bytes_received < length)
        {
            ssize_t bytes = recv(socket, ptr + bytes_received, length - bytes_received, 0);
            if (bytes <= 0)
            {
                return false;
            }
            bytes_received += bytes;
        }
        return true;
    }

    void stream_send_file(int socket, handshake::SessionKeys session_keys, const std::string &local_file_path, const std::string &remote_file_path)
    {
        std::filesystem::path p(remote_file_path);
        std::string remote_file_name = p.filename().string();
        uint64_t local_file_size = std::filesystem::file_size(local_file_path);

        std::string metadata = remote_file_name + "|" + std::to_string(local_file_size);

        std::vector<unsigned char> meta_cipher(metadata.size() + crypto_aead_aes256gcm_ABYTES);
        unsigned long long meta_cipher_size;

        crypto::encrypt_chunk(meta_cipher.data(),
                              &meta_cipher_size,
                              (const unsigned char *)metadata.data(),
                              metadata.size(),
                              nullptr,
                              0,
                              session_keys.session_nonce,
                              session_keys.session_key);

        uint32_t total_metadata_size = htonl(static_cast<uint32_t>(meta_cipher_size));
        send_loop(socket, &total_metadata_size, sizeof(total_metadata_size));
        send_loop(socket, meta_cipher.data(), meta_cipher_size);

        sodium_increment(session_keys.session_nonce, sizeof(session_keys.session_nonce));

        std::ifstream infile(local_file_path, std::ios::binary);
        if (!infile)
            throw std::runtime_error("Cannot open local file.");

        std::vector<unsigned char> buffer(transfer::config::CHUNK_SIZE);
        std::vector<unsigned char> ciphertext(transfer::config::CHUNK_SIZE + crypto_aead_aes256gcm_ABYTES);

        std::cout << "Sending file.\n";
        while (infile)
        {
            infile.read((char *)buffer.data(), buffer.size());
            std::streamsize bytes_read = infile.gcount();
            if (bytes_read == 0)
                break;

            unsigned long long cipher_len;
            if (!crypto::encrypt_chunk(ciphertext.data(), &cipher_len,
                                       buffer.data(), bytes_read,
                                       nullptr, 0, session_keys.session_nonce, session_keys.session_key))
            {
                throw std::runtime_error("Encryption failed during stream.");
            }

            uint32_t chunk_net_size = htonl(static_cast<uint32_t>(cipher_len));
            send_loop(socket, &chunk_net_size, sizeof(chunk_net_size));
            send_loop(socket, ciphertext.data(), cipher_len);

            sodium_increment(session_keys.session_nonce, sizeof(session_keys.session_nonce));
        }

        uint32_t eof = 0;
        send_loop(socket, &eof, sizeof(eof));
        std::cout << "Transfer complete.\n";
    }

    void stream_receive_file(int socket_fd, handshake::SessionKeys keys)
    {
        uint32_t net_size;
        if (!receive_loop(socket_fd, &net_size, sizeof(net_size)))
            throw std::runtime_error("Failed to read metadata size.");
        uint32_t meta_cipher_len = ntohl(net_size);

        std::vector<unsigned char> meta_cipher(meta_cipher_len);
        receive_loop(socket_fd, meta_cipher.data(), meta_cipher_len);

        std::vector<unsigned char> meta_plain(meta_cipher_len - crypto_aead_aes256gcm_ABYTES);
        unsigned long long meta_plain_len;
        crypto::decrypt_chunk(meta_plain.data(), &meta_plain_len,
                              meta_cipher.data(), meta_cipher_len,
                              nullptr, 0, keys.session_nonce, keys.session_key);

        sodium_increment(keys.session_nonce, sizeof(keys.session_nonce));

        std::string metadata_str((char *)meta_plain.data(), meta_plain_len);
        size_t delim = metadata_str.find('|');
        std::string raw_filename = metadata_str.substr(0, delim);

        std::filesystem::path received_path(raw_filename);
        std::string secure_filename = received_path.filename().string();

        std::string save_dir = std::string(getenv("HOME")) + "/.config/qpost/downloads/";
        std::filesystem::create_directories(save_dir);
        std::string final_path = save_dir + secure_filename;

        std::cout << "Receiving file: " << secure_filename << " -> " << final_path << "\n";

        std::ofstream outfile(final_path, std::ios::binary);
        if (!outfile)
            throw std::runtime_error("Cannot create output file.");

        while (true)
        {
            if (!receive_loop(socket_fd, &net_size, sizeof(net_size)))
                break;
            uint32_t cipher_len = ntohl(net_size);

            if (cipher_len == 0)
            {
                std::cout << "Transfer complete.\n";
                break;
            }

            std::vector<unsigned char> ciphertext(cipher_len);
            receive_loop(socket_fd, ciphertext.data(), cipher_len);

            std::vector<unsigned char> plaintext(cipher_len - crypto_aead_aes256gcm_ABYTES);
            unsigned long long plain_len;
            if (!crypto::decrypt_chunk(plaintext.data(), &plain_len,
                                       ciphertext.data(), cipher_len,
                                       nullptr, 0, keys.session_nonce, keys.session_key))
            {
                throw std::runtime_error("Decryption failed.");
            }

            outfile.write((char *)plaintext.data(), plain_len);
            sodium_increment(keys.session_nonce, sizeof(keys.session_nonce));
        }
    }
}
