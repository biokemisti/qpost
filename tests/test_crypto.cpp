#include <vector>
#include <cassert>
#include <iostream>
#include "crypto_utils.hpp"
#include "config.hpp"

int main()
{
    std::cout << "Local crypto tests.\n";

    uint8_t session_key[crypto_aead_aes256gcm_KEYBYTES];
    crypto::random_bytes(session_key, sizeof(session_key));

    uint8_t session_nonce[12];
    crypto::random_bytes(session_nonce, sizeof(session_nonce));

    std::string plaintext = "This is a test.";

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ciphertext_len;

    std::cout << "Original message: " << plaintext << "\n";

    // --- TEST 1: Encryption ---
    bool enc_success = crypto::encrypt_chunk(
        ciphertext.data(), &ciphertext_len,
        (const unsigned char *)plaintext.data(), plaintext.size(),
        nullptr, 0,
        session_nonce, session_key);

    if (enc_success)
    {
        std::cout << "Encryption successful. Ciphertext length: " << ciphertext_len << " bytes.\n";
    }
    else
    {
        std::cerr << "Encryption failed.\n";
        return 1;
    }

    // TEST 2: Decryption
    std::vector<unsigned char> decrypted(ciphertext_len - crypto_aead_aes256gcm_ABYTES);
    unsigned long long decrypted_len;

    bool dec_success = crypto::decrypt_chunk(
        decrypted.data(), &decrypted_len,
        ciphertext.data(), ciphertext_len,
        nullptr, 0,
        session_nonce, session_key);

    if (dec_success)
    {
        std::string decrypted_str((char *)decrypted.data(), decrypted_len);
        std::cout << "Decryption successful! Recovered message: " << decrypted_str << "\n";
        assert(plaintext == decrypted_str && "Decrypted text does not match original!");
    }

    // TEST 3: Tampering
    std::cout << "Modifying 1 byte of ciphertext to simulate tampering/network error...\n";
    ciphertext[5] ^= 0xFF;

    bool tamper_success = crypto::decrypt_chunk(
        decrypted.data(), &decrypted_len,
        ciphertext.data(), ciphertext_len,
        nullptr, 0,
        session_nonce, session_key);

    if (!tamper_success)
    {
        std::cout << "Tamper test passed.\n";
    }
    else
    {
        std::cerr << "Tamper test failed.\n";
        return 1;
    }

    // TEST 4: Incrementing nonce
    sodium_increment(session_nonce, sizeof(session_nonce));
    std::cout << "Nonce incremented.\n";

    std::cout << "All tests passed.\n";
    return 0;
}
