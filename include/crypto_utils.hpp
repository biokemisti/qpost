/**
 * Declarations for cryptography related utilities.
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
    void random_bytes(uint8_t *buffer, std::size_t length);

    // HKDF = HMAC based Key Derivation Function
    // HMAC = Hash based Message Authentication Code
    int derive_session_keys(
        const uint8_t *kyber_shared_secret,
        const uint8_t *x25519_shared_secret,
        const uint8_t *client_nonce,
        const uint8_t *server_nonce,
        uint8_t *session_key,
        uint8_t *session_nonce,
        const uint8_t *pre_shared_key);

    int generate_hmac(const uint8_t *transcript, std::size_t transcript_size, const uint8_t *psk, uint8_t *hmac);

    int verify_hmac(const uint8_t *transcript, std::size_t transcript_size, const uint8_t *psk, const uint8_t *hmac);

    void encrypt_chunk(unsigned char *ciphertext,
                      unsigned long long *ciphertext_size,
                      const unsigned char *message,
                      std::size_t message_size,
                      const unsigned char *additional_data,
                      std::size_t additional_data_size,
                      const uint8_t *nonce,
                      const uint8_t *session_key);

    void decrypt_chunk(unsigned char *message,
                      unsigned long long *message_size,
                      const unsigned char *ciphertext,
                      unsigned long long ciphertext_size,
                      const unsigned char *additional_data,
                      std::size_t additional_data_size,
                      const uint8_t *nonce,
                      const uint8_t *session_key);
}
