/**
 * Configuration file for qpost. Size constants, supported algorithms, etc.
 *
 * @author Elmo Moilanen
 */

#pragma once

namespace handshake::config
{
    constexpr std::size_t PRE_SHARED_KEY_SIZE = 32; // Size of the pre-shared secret
    constexpr std::size_t HMAC_TAG_SIZE = 32;       // Size of the HMAC tag

    constexpr std::size_t KYBER_PUBLIC_KEY_SIZE = 1184;  // Size of the Kyber public key
    constexpr std::size_t KYBER_CIPHERTEXT_SIZE = 1088;  // Size of the Kyber ciphertext
    constexpr std::size_t KYBER_SECRET_KEY_SIZE = 2400;  // size of the Kyber secret key
    constexpr std::size_t KYBER_SHARED_SECRET_SIZE = 32; // Size of the Kyber shared secret

    constexpr std::size_t NONCE_SIZE = 32; // Size of the random number used once

    constexpr std::size_t X25519_PUBLIC_KEY_SIZE = 32;    // Size of the X25519 public keys
    constexpr std::size_t X25519_SHARED_SECRET_SIZE = 32; // Size of the X25519 shared secret

    constexpr std::size_t SESSION_KEY_SIZE = 32; // Size of session keys

    constexpr uint8_t X25519 = 0b00000001; // Only X25519
    constexpr uint8_t KYBER = 0b00000010;  // Only Kyber
    constexpr uint8_t HYBRID = 0b00000011; // Both x25519 and Kyber
}

namespace transfer::config
{
    constexpr std::size_t NONCE_SIZE = 12;    // Required by AES-GCM
    constexpr std::size_t CHUNK_SIZE = 65536; // 64KB
}
