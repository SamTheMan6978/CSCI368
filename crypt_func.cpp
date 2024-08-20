#define OPENSSL_SUPPRESS_DEPRECATED 1

#include "crypt_func.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

// General error handling function
void handleError(const std::string& message) {
    std::cerr << message << ": " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
}

// Base64 Encoding and Decoding
std::string base64(const std::string& input, Base64Operation operation) {
    BIO* bio = nullptr;
    BIO* b64 = nullptr;
    std::string output;

    if (operation == Base64Operation::Encode) {
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        // Ignore newlines
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, input.data(), input.size());
        BIO_flush(bio);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        output.assign(bufferPtr->data, bufferPtr->length);

        // Trim any potential null characters or extra padding (if necessary)
        output.erase(output.find_last_not_of("\0") + 1);
    }
    else if (operation == Base64Operation::Decode) {
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.data(), input.size());
        bio = BIO_push(b64, bio);

        // Ignore newlines
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        std::vector<unsigned char> decodedBuffer(input.size());
        int length = BIO_read(bio, decodedBuffer.data(), decodedBuffer.size());

        if (length > 0) {
            output.assign(decodedBuffer.begin(), decodedBuffer.begin() + length);
        }
    }

    BIO_free_all(bio);
    return output;
}

std::string base64(const std::vector<unsigned char>& input, Base64Operation operation) {
    return base64(std::string(input.begin(), input.end()), operation);
}

std::vector<unsigned char> base64ToVector(const std::string& input, Base64Operation operation) {
    std::string decodedString = base64(input, operation);
    if (decodedString.empty()) {
        std::cerr << "Base64 decoding resulted in an empty string." << std::endl;
    }
    return std::vector<unsigned char>(decodedString.begin(), decodedString.end());
}

std::string vectorToBase64(const std::vector<unsigned char>& input, Base64Operation operation) {
    return base64(std::string(input.begin(), input.end()), operation);
}

// Function to sanitize Base64 strings by removing any non-Base64 characters
std::string sanitizeBase64(const std::string& input) {
    std::string sanitized;
    std::copy_if(input.begin(), input.end(), std::back_inserter(sanitized), [](unsigned char c) {
        return isalnum(c) || c == '+' || c == '/' || c == '=';
        });
    return sanitized;
}

// SHA-1 Hashing
std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

// RC4 Encryption and Decryption
std::string rc4(const std::string& key, const std::string& data) {
    RC4_KEY rc4Key;
    std::string output(data.size(), '\0');

    if (key.empty() || data.empty()) {
        std::cerr << "RC4 key or data is empty!" << std::endl;
        return output;  // Early return if the key or data is invalid
    }

    // Initialize RC4 key
    RC4_set_key(&rc4Key, key.size(), reinterpret_cast<const unsigned char*>(key.data()));

    // Encrypt or decrypt the data
    RC4(&rc4Key, data.size(), reinterpret_cast<const unsigned char*>(data.data()), reinterpret_cast<unsigned char*>(&output[0]));

    return output;
}

// Conversion functions between string and vector
std::vector<unsigned char> stringToVector(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

std::string vectorToString(const std::vector<unsigned char>& vec) {
    return std::string(vec.begin(), vec.end());
}

// RSA Encryption
std::string encryptRSA(const std::string& publicKeyFile, const std::string& plaintext) {
    BIO* bio = BIO_new_file(publicKeyFile.c_str(), "r");
    if (!bio) {
        handleError("Error opening public key file");
        return "";
    }

    EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pubkey) {
        handleError("Error loading public key");
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    if (!ctx) {
        handleError("Error creating encryption context");
        EVP_PKEY_free(pubkey);
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handleError("Error initializing encryption with padding");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) <= 0) {
        handleError("Error determining buffer size");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) <= 0) {
        handleError("Error encrypting data");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    return base64(ciphertext, Base64Operation::Encode);
}

// RSA Decryption
std::string decryptRSA(const std::string& privateKeyFile, const std::string& ciphertext) {
    BIO* bio = BIO_new_file(privateKeyFile.c_str(), "r");
    if (!bio) {
        handleError("Error opening private key file");
        return "";
    }

    EVP_PKEY* privkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!privkey) {
        handleError("Error loading private key");
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!ctx) {
        handleError("Error creating decryption context");
        EVP_PKEY_free(privkey);
        return "";
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handleError("Error initializing decryption with padding");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return "";
    }

    std::string decodedCiphertext = base64(ciphertext, Base64Operation::Decode);
    std::vector<unsigned char> decodedCiphertextVec(stringToVector(decodedCiphertext));

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, decodedCiphertextVec.data(), decodedCiphertextVec.size()) <= 0) {
        handleError("Error determining buffer size");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return "";
    }

    std::vector<unsigned char> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, decodedCiphertextVec.data(), decodedCiphertextVec.size()) <= 0) {
        handleError("Error decrypting data");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);

    return std::string(plaintext.begin(), plaintext.end());
}

// Load RSA key (public or private)
EVP_PKEY* loadKey(const std::string& keyFile, bool isPublic) {
    BIO* bio = BIO_new_file(keyFile.c_str(), "r");
    if (!bio) {
        handleError("Unable to open key file: " + keyFile);
        return nullptr;
    }

    EVP_PKEY* pkey = isPublic ? PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr)
        : PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        handleError("Error reading key from file: " + keyFile);
        return nullptr;
    }

    return pkey;
}

// Fingerprint Verification
bool verifyFingerprint(const std::string& publicKey) {
    std::string aliceFingerprint = sha1(publicKey);

    std::ifstream fingerprintFile("Bob/fingerprint.txt");
    if (!fingerprintFile.is_open()) {
        std::cerr << "Error opening fingerprint file for reading." << std::endl;
        return false;
    }

    std::string storedFingerprint;
    std::getline(fingerprintFile, storedFingerprint);
    fingerprintFile.close();

    storedFingerprint.erase(std::remove_if(storedFingerprint.begin(), storedFingerprint.end(), ::isspace), storedFingerprint.end());

    if (aliceFingerprint != storedFingerprint) {
        std::cerr << "Public key fingerprint does not match. Terminating connection." << std::endl;
        return false;
    }

    return true;
}

// Nonce Generation
std::string generateNonce(int length) {
    std::vector<unsigned char> nonce(length);
    if (RAND_bytes(nonce.data(), length) != 1) {
        handleError("Failed to generate nonce");
        return "";
    }

    return base64(nonce, Base64Operation::Encode);
}

// Public Key Serialization
std::string serializePublicKey(EVP_PKEY* pubkey) {
    if (!pubkey) {
        std::cerr << "Public key is null" << std::endl;
        return "";
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        handleError("Failed to create BIO");
        return "";
    }

    if (PEM_write_bio_PUBKEY(bio, pubkey) <= 0) {
        handleError("Failed to write public key to BIO");
        BIO_free(bio);
        return "";
    }

    BUF_MEM* buf_mem = nullptr;
    BIO_get_mem_ptr(bio, &buf_mem);
    std::string publicKeyStr(buf_mem->data, buf_mem->length);

    BIO_free(bio);
    return publicKeyStr;
}
