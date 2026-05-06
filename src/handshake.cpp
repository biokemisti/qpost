/**
 * Client and server handshakes.
 *
 * @author Elmo Moilanen
 */

#include <sys/socket.h>
#include <iostream>
#include <sodium.h>
#include <cstring>
#include <oqs/oqs.h>
#include <optional>
#include "handshake.hpp"
#include "crypto_utils.hpp"

std::optional<handshake::SessionKeys> handshake::client_handshake(int socket, const uint8_t *pre_shared_key, uint8_t algorithm)
{
    // Initialize open quantum safe
    OQS_init();

    // -------------------- CLIENT HELLO --------------------
    // Generate nonce for client hello
    handshake::ClientHello client_hello{};
    crypto::random_bytes(client_hello.client_nonce, handshake::config::NONCE_SIZE);

    // Add supported alogrithms to the client hello
    client_hello.supported_algorithms = algorithm;

    // Send client hello over TCP
    send(socket, &client_hello, sizeof(client_hello), 0);
    std::cout << "Client hello sent.\n";

    // Receive the server hello message:
    // nonce, kyber public key, X25519 public key
    handshake::ServerHello server_hello{};
    ssize_t received = recv(socket, &server_hello, sizeof(server_hello), MSG_WAITALL);
    if (received != sizeof(server_hello))
    {
        std::cout << "Server hello not received.\n";
        return handshake::SessionKeys{};
    }
    std::cout << "Server hello received.\n";

    // -------------------- CLIENT KEYSHARE --------------------
    // Client X25519 keypair generation
    unsigned char client_x25519_private_key[crypto_scalarmult_SCALARBYTES];
    unsigned char client_x25519_public_key[crypto_scalarmult_BYTES];
    crypto_box_keypair(client_x25519_public_key, client_x25519_private_key);

    // Create X25519 shared secret
    unsigned char x25519_shared_secret[handshake::config::X25519_SHARED_SECRET_SIZE];
    if (crypto_scalarmult(x25519_shared_secret, client_x25519_private_key, server_hello.server_x25519_public_key) != 0)
    {
        std::cout << "Failed to derive X25519 shared secret.\n";
        return handshake::SessionKeys{};
    }

    // Encapsulation
    // Use the server's public key to encapsulate ciphertext
    uint8_t kyber_shared_secret[handshake::config::KYBER_SHARED_SECRET_SIZE];
    uint8_t kyber_ciphertext_encapsulated[handshake::config::KYBER_CIPHERTEXT_SIZE];
    if (OQS_KEM_ml_kem_768_encaps(kyber_ciphertext_encapsulated, kyber_shared_secret, server_hello.server_kyber_public_key) != OQS_SUCCESS)
    {
        std::cout << "Kyber ciphertext encapsulation failed\n";
    }

    // Store encapsulated Kyber ciphertext and X25519 public key in client keyshare
    handshake::ClientKeyShare client_keyshare{};
    memcpy(client_keyshare.kyber_ciphertext_encapsulated, kyber_ciphertext_encapsulated, handshake::config::KYBER_CIPHERTEXT_SIZE);
    memcpy(client_keyshare.x25519_public_key, client_x25519_public_key, handshake::config::X25519_PUBLIC_KEY_SIZE);

    std::size_t client_transcript_size = sizeof(client_hello) + sizeof(server_hello) + handshake::config::X25519_PUBLIC_KEY_SIZE + handshake::config::KYBER_CIPHERTEXT_SIZE;
    std::uint8_t client_transcript[client_transcript_size];

    std::size_t client_transcript_offset = 0;

    memcpy(client_transcript, &client_hello, sizeof(client_hello));
    client_transcript_offset += sizeof(client_hello);
    memcpy(client_transcript + client_transcript_offset, &server_hello, sizeof(server_hello));
    client_transcript_offset += sizeof(server_hello);
    memcpy(client_transcript + client_transcript_offset, client_keyshare.x25519_public_key, handshake::config::X25519_PUBLIC_KEY_SIZE);
    client_transcript_offset += handshake::config::X25519_PUBLIC_KEY_SIZE;
    memcpy(client_transcript + client_transcript_offset, client_keyshare.kyber_ciphertext_encapsulated, handshake::config::KYBER_CIPHERTEXT_SIZE);
    client_transcript_offset += handshake::config::KYBER_CIPHERTEXT_SIZE;

    crypto::generate_hmac(client_transcript, client_transcript_size, pre_shared_key, client_keyshare.hmac);

    // Send client keyshare
    send(socket, &client_keyshare, sizeof(client_keyshare), 0);
    std::cout << "Client keyshare sent.\n";

    // ------- RECEIVE AND VERIFT SERVER FINISHED MESSAGE -------
    handshake::FinishedMessage server_finished{};
    if (recv(socket, &server_finished, sizeof(server_finished), MSG_WAITALL) != sizeof(server_finished))
    {
        std::cout << "Failed to receive ServerFinished.\n";
        return std::nullopt;
    }

    std::size_t final_transcript_size = sizeof(client_hello) + sizeof(server_hello) + sizeof(client_keyshare);
    uint8_t final_transcript[final_transcript_size];
    std::size_t final_transcript_offset = 0;

    memcpy(final_transcript + final_transcript_offset, &client_hello, sizeof(client_hello));
    final_transcript_offset += sizeof(client_hello);
    memcpy(final_transcript + final_transcript_offset, &server_hello, sizeof(server_hello));
    final_transcript_offset += sizeof(server_hello);
    memcpy(final_transcript + final_transcript_offset, &client_keyshare, sizeof(client_keyshare));

    if (crypto::verify_hmac(final_transcript, final_transcript_size, pre_shared_key, server_finished.hmac) != 0)
    {
        std::cout << "Server HMAC verification failed.\n";
        return std::nullopt;
    }
    std::cout << "Server authenticated successfully.\n";

    // ------------------ DERIVE SESSION KEYS ------------------
    handshake::SessionKeys session_keys{};
    if (crypto::derive_session_keys(
            kyber_shared_secret,
            x25519_shared_secret,
            client_hello.client_nonce,
            server_hello.server_nonce,
            session_keys.session_key,
            session_keys.session_nonce,
            pre_shared_key) != 0)
    {
        std::cout << "Session key derivation failed.\n";
        return std::nullopt;
    }
    std::cout << "Session keys derived.\n";

    // Erase shared secrets from memory since they are no longer needed
    sodium_memzero(kyber_shared_secret, sizeof(kyber_shared_secret));
    sodium_memzero(x25519_shared_secret, sizeof(x25519_shared_secret));

    return session_keys;
}

std::optional<handshake::SessionKeys> handshake::server_handshake(int socket, const uint8_t *pre_shared_key)
{
    // Initialize open quantum safe
    OQS_init();

    // Wait for the client hello message
    handshake::ClientHello client_hello{};
    ssize_t received_client_hello = recv(socket, &client_hello, sizeof(client_hello), MSG_WAITALL);
    if (received_client_hello != sizeof(client_hello))
    {
        std::cout << "Client hello not received.\n";
        return handshake::SessionKeys{};
    }
    std::cout << "Client hello received.\n";

    // -------------------- SERVER HELLO --------------------

    // Choose the cryptographic algorithm
    handshake::ServerHello server_hello{};
    server_hello.chosen_algorithm = client_hello.supported_algorithms;

    // Generate and store nonce in server_hello
    crypto::random_bytes(server_hello.server_nonce, handshake::config::NONCE_SIZE);

    // Generate asymmetric x25519 keys
    unsigned char server_x25519_private_key[crypto_scalarmult_SCALARBYTES];
    unsigned char server_x25519_public_key[crypto_scalarmult_BYTES];
    crypto_box_keypair(server_x25519_public_key, server_x25519_private_key);

    // Store x25519 public key in server_hello
    memcpy(server_hello.server_x25519_public_key, server_x25519_public_key, handshake::config::X25519_PUBLIC_KEY_SIZE);

    // Generate Kyber keypair
    uint8_t server_kyber_public_key[handshake::config::KYBER_PUBLIC_KEY_SIZE];
    uint8_t server_kyber_secret_key[handshake::config::KYBER_SECRET_KEY_SIZE];

    if (OQS_KEM_ml_kem_768_keypair(server_kyber_public_key, server_kyber_secret_key) != OQS_SUCCESS)
    {
        std::cout << "Kyber keypair generation failed.\n";
    }

    // Store kyber public key in server_hello
    memcpy(server_hello.server_kyber_public_key, server_kyber_public_key, handshake::config::KYBER_PUBLIC_KEY_SIZE);

    // Send server hello
    send(socket, &server_hello, sizeof(server_hello), 0);
    std::cout << "Server hello sent.\n";

    // -------------------------------------------------------

    // --------------- RECEIVE AND VERIFY CLIENT KEYSHARE ---------------
    handshake::ClientKeyShare client_keyshare{};
    ssize_t received_client_keyshare = recv(socket, &client_keyshare, sizeof(client_keyshare), MSG_WAITALL);
    if (received_client_keyshare != sizeof(client_keyshare))
    {
        std::cout << "Client keyshare not received.\n";
        return handshake::SessionKeys{};
    }
    std::cout << "Client keyshare received.\n";

    std::size_t client_transcript_size = sizeof(client_hello) + sizeof(server_hello) +
                                         handshake::config::X25519_PUBLIC_KEY_SIZE +
                                         handshake::config::KYBER_CIPHERTEXT_SIZE;

    uint8_t client_transcript[client_transcript_size];
    std::size_t client_transcript_offset = 0;

    memcpy(client_transcript + client_transcript_offset, &client_hello, sizeof(client_hello));
    client_transcript_offset += sizeof(client_hello);
    memcpy(client_transcript + client_transcript_offset, &server_hello, sizeof(server_hello));
    client_transcript_offset += sizeof(server_hello);
    memcpy(client_transcript + client_transcript_offset, client_keyshare.x25519_public_key, handshake::config::X25519_PUBLIC_KEY_SIZE);
    client_transcript_offset += handshake::config::X25519_PUBLIC_KEY_SIZE;
    memcpy(client_transcript + client_transcript_offset, client_keyshare.kyber_ciphertext_encapsulated, handshake::config::KYBER_CIPHERTEXT_SIZE);

    if (crypto::verify_hmac(client_transcript, client_transcript_size, pre_shared_key, client_keyshare.hmac) != 0)
    {
        std::cout << "Client HMAC verification failed.\n";
        return std::nullopt;
    }
    std::cout << "Client authenticated successfully.\n";

    // ------------- SEND ServerFinished MESSAGE -------------
    handshake::FinishedMessage server_finished{};
    std::size_t final_transcript_size = sizeof(client_hello) + sizeof(server_hello) + sizeof(client_keyshare);
    uint8_t final_transcript[final_transcript_size];
    std::size_t final_transcript_offset = 0;

    memcpy(final_transcript + final_transcript_offset, &client_hello, sizeof(client_hello));
    final_transcript_offset += sizeof(client_hello);
    memcpy(final_transcript + final_transcript_offset, &server_hello, sizeof(server_hello));
    final_transcript_offset += sizeof(server_hello);
    memcpy(final_transcript + final_transcript_offset, &client_keyshare, sizeof(client_keyshare));

    crypto::generate_hmac(final_transcript, final_transcript_size, pre_shared_key, server_finished.hmac);
    send(socket, &server_finished, sizeof(server_finished), 0);
    std::cout << "ServerFinished sent.\n";

    // ----------------- DERIVE SessionKeys ------------------
    // Derive X25519 shared secret
    unsigned char x25519_shared_secret[handshake::config::X25519_SHARED_SECRET_SIZE];
    if (crypto_scalarmult(x25519_shared_secret, server_x25519_private_key, client_keyshare.x25519_public_key) != 0)
    {
        std::cout << "Failed to derive X25519 shared secret.\n";
        return handshake::SessionKeys{};
    }

    // Decapsulate kyber shared secret
    uint8_t kyber_shared_secret[handshake::config::KYBER_SHARED_SECRET_SIZE];
    if (OQS_KEM_ml_kem_768_decaps(kyber_shared_secret, client_keyshare.kyber_ciphertext_encapsulated, server_kyber_secret_key) != OQS_SUCCESS)
    {
        std::cout << "Kyber keypair generation failed.\n";
        return handshake::SessionKeys{};
    }

    handshake::SessionKeys session_keys{};
    if (crypto::derive_session_keys(
            kyber_shared_secret,
            x25519_shared_secret,
            client_hello.client_nonce,
            server_hello.server_nonce,
            session_keys.session_key,
            session_keys.session_nonce,
            pre_shared_key) != 0)
    {
        std::cout << "Session key derivation failed.\n";
        return std::nullopt;
    }
    std::cout << "Session keys derived.\n";

    // Erase shared secrets from memory since they are no longer needed
    sodium_memzero(kyber_shared_secret, sizeof(kyber_shared_secret));
    sodium_memzero(x25519_shared_secret, sizeof(x25519_shared_secret));

    return session_keys;
}
