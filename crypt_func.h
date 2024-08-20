#pragma once

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rsa.h>

// Error Handling
// Logs an error message with the OpenSSL error string
void handleError(const std::string& message);

// RSA Encryption and Decryption
// Encrypts the given plaintext using the provided RSA public key file
std::string encryptRSA(const std::string& publicKeyFile, const std::string& plaintext);

// Decrypts the given ciphertext using the provided RSA private key file
std::string decryptRSA(const std::string& privateKeyFile, const std::string& ciphertext);

// Loads an RSA key (public or private) from the specified file
EVP_PKEY* loadKey(const std::string& keyFile, bool isPublic);

// Fingerprint Verification
// Verifies the provided public key against the stored fingerprint
bool verifyFingerprint(const std::string& publicKey);

// Base64 Encoding and Decoding
// Enum to specify the operation: Encode or Decode
enum class Base64Operation { Encode, Decode };

// Encodes or decodes the given string using Base64
std::string base64(const std::string& input, Base64Operation operation);

// Encodes or decodes the given vector of unsigned chars using Base64
std::string base64(const std::vector<unsigned char>& input, Base64Operation operation);

// Decodes the given Base64 string into a vector of unsigned chars
std::vector<unsigned char> base64ToVector(const std::string& input, Base64Operation operation);

// Encodes the given vector of unsigned chars into a Base64 string
std::string vectorToBase64(const std::vector<unsigned char>& input, Base64Operation operation);

// Removes non-Base64 characters from the input string
std::string sanitizeBase64(const std::string& input);

// SHA-1 Hashing
// Generates a SHA-1 hash of the given input string
std::string sha1(const std::string& input);

// RC4 Encryption and Decryption
// Encrypts or decrypts the given data using the provided RC4 key
std::string rc4(const std::string& key, const std::string& data);

// Utility functions for converting between strings and vectors of unsigned chars
// Converts a string to a vector of unsigned chars
std::vector<unsigned char> stringToVector(const std::string& str);

// Converts a vector of unsigned chars to a string
std::string vectorToString(const std::vector<unsigned char>& vec);

// Nonce Generation
// Generates a random nonce of the specified length
std::string generateNonce(int length);

// Public Key Serialization
// Serializes the provided EVP_PKEY public key to a PEM-formatted string
std::string serializePublicKey(EVP_PKEY* pubkey);

