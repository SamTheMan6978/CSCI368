#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define mkdir _mkdir
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

// Platform-independent directory creation
void createDirectory(const std::string& path) {
#ifdef _WIN32
    mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0777);
#endif
}

// Function to check if a string is alphanumeric
bool isAlphanumeric(const std::string& str) {
    for (char c : str) {
        if (!std::isalnum(c)) {
            return false;
        }
    }
    return true;
}

// Function to validate the password
// Ensures that the password is at least 8 characters long and alphanumeric
bool isValidPassword(const std::string& password) {
    return password.length() >= 8 && isAlphanumeric(password);
}

// Function to hash a password using SHA-1
// Converts the password into a SHA-1 hash represented as a hex string
std::string hashPassword(const std::string& password) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// Function to store username and hashed password in a file
// Prompts the user for a username and password, validates the password, hashes it, and then stores it in the specified file
void storePasswordFile(const std::string& filePath) {
    std::ofstream passwordFile(filePath);
    if (!passwordFile.is_open()) {
        std::cerr << "Error opening password file for writing." << std::endl;
        return;
    }

    std::string username, password;
    std::cout << "Enter your username for storage: ";
    std::cin >> username;

    // Loop until a valid password is entered
    while (true) {
        std::cout << "Enter your password for storage (minimum 8 alphanumeric characters): ";
        std::cin >> password;

        if (isValidPassword(password)) {
            break;
        }
        else {
            std::cout << "Password must be at least 8 alphanumeric characters. Please try again." << std::endl;
        }
    }

    std::string hashedPassword = hashPassword(password);
    passwordFile << username << "," << hashedPassword << std::endl;
    passwordFile.close();
    std::cout << "Password file created and password stored successfully." << std::endl;
}

// Helper function to compute SHA1 hash and return it as a hex string
// This is used to generate a fingerprint for public keys
std::string sha1ToHex(const unsigned char* data, size_t length) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, length, hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// Function to write a private key to a file
// Takes an EVP_PKEY structure and writes it to the specified file in PEM format
bool writePrivateKey(EVP_PKEY* pkey, const std::string& filePath) {
    BIO* privBio = BIO_new_file(filePath.c_str(), "wb");
    if (!privBio) {
        std::cerr << "Error opening private key file for writing." << std::endl;
        return false;
    }

    if (!PEM_write_bio_PrivateKey(privBio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Error writing private key." << std::endl;
        BIO_free(privBio);
        return false;
    }

    BIO_free(privBio);
    return true;
}

// Function to write a public key to a file and return its fingerprint
// The public key is written to the specified file, and its fingerprint is computed and returned
std::string writePublicKeyAndGetFingerprint(EVP_PKEY* pkey, const std::string& filePath) {
    BIO* pubBio = BIO_new(BIO_s_mem());
    if (!pubBio || !PEM_write_bio_PUBKEY(pubBio, pkey)) {
        std::cerr << "Error writing public key." << std::endl;
        if (pubBio) BIO_free(pubBio);
        return "";
    }

    BUF_MEM* pubKeyMemPtr;
    BIO_get_mem_ptr(pubBio, &pubKeyMemPtr);

    BIO* pubFileBio = BIO_new_file(filePath.c_str(), "wb");
    if (!pubFileBio) {
        std::cerr << "Error opening public key file for writing." << std::endl;
        BIO_free(pubBio);
        return "";
    }

    BIO_write(pubFileBio, pubKeyMemPtr->data, pubKeyMemPtr->length);
    BIO_free(pubFileBio);

    std::string fingerprint = sha1ToHex(reinterpret_cast<const unsigned char*>(pubKeyMemPtr->data), pubKeyMemPtr->length);
    BIO_free(pubBio);
    return fingerprint;
}

// Function to generate and store RSA keys along with their fingerprint
// This function generates an RSA key pair, stores the private and public keys in separate files, and records the public key's fingerprint
void generateRSAKeys() {
    // Step 1: Create directories for Alice and Bob if they do not exist
    createDirectory("Alice");
    createDirectory("Bob");

    // Step 2: Store a username and password hash for Alice
    storePasswordFile("Alice/password.txt");

    // Step 3: Generate an RSA key pair
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating RSA key pair." << std::endl;
        if (ctx) EVP_PKEY_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        return;
    }
    EVP_PKEY_CTX_free(ctx);

    // Step 4: Write the private key to a file
    if (!writePrivateKey(pkey, "Alice/private.pem")) {
        EVP_PKEY_free(pkey);
        return;
    }

    // Step 5: Write the public key to a file and retrieve its fingerprint
    std::string fingerprint = writePublicKeyAndGetFingerprint(pkey, "Alice/public.pem");
    if (fingerprint.empty()) {
        EVP_PKEY_free(pkey);
        return;
    }

    // Step 6: Store the public key fingerprint in Bob's directory
    std::ofstream fingerprintFile("Bob/fingerprint.txt");
    if (fingerprintFile.is_open()) {
        fingerprintFile << fingerprint;
        fingerprintFile.close();
        std::cout << "Public key fingerprint stored successfully." << std::endl;
    }
    else {
        std::cerr << "Error opening fingerprint file for writing." << std::endl;
    }

    EVP_PKEY_free(pkey);
}

int main() {
    // Main function to generate RSA keys and display a success message
    generateRSAKeys();
    std::cout << "Keys generated and stored." << std::endl;
    return 0;
}
