/**
 * Utilities related to cryptography. Random number generation,
 * session key derivation, etc.
 *
 * @author Elmo Moilanen
 */

#include <iostream>
#include "crypto_utils.hpp"

namespace crypto
{
    void random_bytes(uint8_t *buffer, std::size_t length)
    {
        randombytes_buf(buffer, length);
    }

    int derive_session_keys(
        const uint8_t *kyber_shared_secret,
        const uint8_t *x25519_shared_secret,
        const uint8_t *client_nonce,
        const uint8_t *server_nonce,
        uint8_t *session_key,
        uint8_t *session_nonce,
        const uint8_t *pre_shared_key)
    {

        // Combine Kyber and X25519 shared secrets with the pre-shared key to create input keying material
        uint8_t input_keying_material[handshake::config::KYBER_SHARED_SECRET_SIZE + handshake::config::X25519_SHARED_SECRET_SIZE + handshake::config::PRE_SHARED_KEY_SIZE];

        size_t ikm_size = 0;

        memcpy(input_keying_material, kyber_shared_secret, handshake::config::KYBER_SHARED_SECRET_SIZE);
        ikm_size += handshake::config::KYBER_SHARED_SECRET_SIZE;

        memcpy(input_keying_material + ikm_size, x25519_shared_secret, handshake::config::X25519_SHARED_SECRET_SIZE);
        ikm_size += handshake::config::X25519_SHARED_SECRET_SIZE;

        memcpy(input_keying_material + ikm_size, pre_shared_key, handshake::config::PRE_SHARED_KEY_SIZE);

        // Combine the client and server nonces
        uint8_t salt[handshake::config::NONCE_SIZE * 2];
        memcpy(salt, client_nonce, handshake::config::NONCE_SIZE);
        memcpy(salt + handshake::config::NONCE_SIZE, server_nonce, handshake::config::NONCE_SIZE);

        // Create a pseudorandom key with shared secrets and salt
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

    int generate_hmac(const uint8_t *transcript, std::size_t transcript_size, const uint8_t *psk, uint8_t *hmac)
    {
        return crypto_auth(hmac, transcript, transcript_size, psk);
    }

    int verify_hmac(const uint8_t *transcript, std::size_t transcript_size, const uint8_t *psk, const uint8_t *hmac)
    {
        return crypto_auth_verify(hmac, transcript, transcript_size, psk);
    }

    void encrypt_chunk(unsigned char *ciphertext,
                       unsigned long long *ciphertext_size,
                       const unsigned char *message,
                       std::size_t message_size,
                       const unsigned char *additional_data,
                       std::size_t additional_data_size,
                       const uint8_t *nonce,
                       const uint8_t *session_key)
    {
        try
        {
            if (crypto_aead_aes256gcm_is_available() == 0)
            {
                throw std::runtime_error("AES-256-GCM not available for this CPU.");
            }

            if (crypto_aead_aes256gcm_encrypt(ciphertext,
                                              ciphertext_size,
                                              message,
                                              message_size,
                                              additional_data,
                                              additional_data_size,
                                              NULL,
                                              nonce,
                                              session_key) < 0)
            {
                throw std::runtime_error("Failed to encrypt chunk.");
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << "\n";
        }
    }

    void decrypt_chunk(unsigned char *message,
                       unsigned long long *message_size,
                       const unsigned char *ciphertext,
                       unsigned long long ciphertext_size,
                       const unsigned char *additional_data,
                       std::size_t additional_data_size,
                       const uint8_t *nonce,
                       const uint8_t *session_key)
    {
        try
        {
            if (crypto_aead_aes256gcm_is_available() == 0)
            {
                throw std::runtime_error("AES-256-GCM not available for this CPU.");
            }

            if (crypto_aead_aes256gcm_decrypt(message,
                                              message_size,
                                              NULL,
                                              ciphertext,
                                              ciphertext_size,
                                              additional_data,
                                              additional_data_size,
                                              nonce,
                                              session_key) < 0)
            {
                throw std::runtime_error("Failed to decrypt chunk.");
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << "\n";
        }
    }
}
