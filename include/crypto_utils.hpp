/**
 * Utilities related to cryptography. Random number generation, etc.
 *
 * @author Elmo Moilanen
 */

#pragma once

#include <cstdint>
#include <sodium.h>
#include <cstring>
#include "config.hpp"

namespace crypto
{
    // Generates random bytes
    inline void random_bytes(uint8_t *buffer, std::size_t length)
    {
        randombytes_buf(buffer, length);
    }

    // HKDF = HMAC based key derivation function
    // HMAC = hash based message authentication code
    int derive_session_keys(
        const uint8_t *kyber_shared_secret,
        const uint8_t *x25519_shared_secret,
        const uint8_t *client_nonce,
        const uint8_t *server_nonce,
        uint8_t *session_key,
        uint8_t *session_nonce)
    {
        // Combine the Kyber and X25519 shared secrets
        uint8_t input_keying_material[handshake::config::KYBER_SHARED_SECRET_SIZE + handshake::config::X25519_SHARED_SECRET_SIZE];
        memcpy(input_keying_material, kyber_shared_secret, handshake::config::KYBER_SHARED_SECRET_SIZE);
        memcpy(input_keying_material + handshake::config::KYBER_SHARED_SECRET_SIZE, x25519_shared_secret, handshake::config::X25519_SHARED_SECRET_SIZE);

        // Combine the client and server nonces
        uint8_t salt[handshake::config::NONCE_SIZE * 2];
        memcpy(salt, client_nonce, handshake::config::NONCE_SIZE);
        memcpy(salt + handshake::config::NONCE_SIZE, server_nonce, handshake::config::NONCE_SIZE);

        // Create a pseudorandom key with shared secrets and nonces
        uint8_t pseudorandom_key[crypto_kdf_hkdf_sha256_KEYBYTES];
        if (crypto_kdf_hkdf_sha256_extract(pseudorandom_key, salt, sizeof(salt), input_keying_material, sizeof(input_keying_material)) != 0)
        {
            std::cout << "Failed to create pseudorandom key.\n";
            return -1;
        }

        // Info strings ensure that they key and nonce are different
        const char *info_key = "session_key";
        const char *info_nonce = "session_nonce";

        // Derive session key and store in session keys
        if (crypto_kdf_hkdf_sha256_expand(
                session_key,
                handshake::config::SESSION_KEY_SIZE,
                info_key,
                strlen(info_key),
                pseudorandom_key) != 0)
        {
            std::cout << "Failed to derive session key.\n";
            return -1;
        }

        // Derive session nonce and store in session keys
        if (crypto_kdf_hkdf_sha256_expand(
                session_nonce,
                handshake::config::NONCE_SIZE,
                info_nonce,
                strlen(info_nonce),
                pseudorandom_key) != 0)
        {
            std::cout << "Failed to derive session nonce.\n";
            return -1;
        }

        // Erase ikm and prk since they are not needed
        sodium_memzero(input_keying_material, sizeof(input_keying_material));
        sodium_memzero(pseudorandom_key, sizeof(pseudorandom_key));

        std::cout << "Successfully derived session key and nonce.\n";

        return 0;
    }
}
