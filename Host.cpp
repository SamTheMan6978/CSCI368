#ifdef _WIN32
#include "../Crypt Func/crypt_func.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include "crypt_func.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#define SOCKET int
#define INVALID_SOCKET -1
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rsa.h>

constexpr int HOST_PORT = 5555;
constexpr int BUFFER_SIZE = 1024;

// Function Declarations
bool initializeWinsock();
SOCKET createAndBindSocket(sockaddr_in& serverAddr);
void sendMessage(SOCKET socket, const std::string& message, const sockaddr_in& addr);
std::string receiveMessage(SOCKET socket, sockaddr_in& addr, int& addrLen);
std::string processPasswordFile();
bool authenticateClient(const std::string& receivedPassword, const std::string& storedLine);
void handleClient(SOCKET clientSocket, EVP_PKEY* privateKey);
bool secureCommunicationLoop(SOCKET clientSocket, const std::string& ssk, sockaddr_in& clientAddr, int& clientAddrLen);

// Main function to set up the server and start listening for clients
int main() {
    // Step 1: Initialize Winsock
    if (!initializeWinsock()) return 1;

    // Step 2: Create and bind the server socket to the specified port
    sockaddr_in serverAddr;
    SOCKET listenSocket = createAndBindSocket(serverAddr);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port " << HOST_PORT << std::endl;

    // Step 3: Load Alice's private key for decrypting messages
    EVP_PKEY* privateKey = loadKey("Alice/private.pem", false);
    if (!privateKey) {
        std::cerr << "Failed to load private key" << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    // Step 4: Continuously handle client connections
    while (true) {
        handleClient(listenSocket, privateKey);
    }

    // Cleanup: Free resources and close sockets
    EVP_PKEY_free(privateKey);
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}

// Initialize Winsock for network communication
bool initializeWinsock() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return false;
    }
#endif
    return true;
}

// Create and bind the server socket
SOCKET createAndBindSocket(sockaddr_in& serverAddr) {
    SOCKET listenSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        return INVALID_SOCKET;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(HOST_PORT);

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        return INVALID_SOCKET;
    }

    return listenSocket;
}

// Send a message to the client
void sendMessage(SOCKET socket, const std::string& message, const sockaddr_in& addr) {
    if (sendto(socket, message.c_str(), message.size(), 0, (const sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Send failed: " << WSAGetLastError() << std::endl;
    }
}

// Receive a message from the client
std::string receiveMessage(SOCKET socket, sockaddr_in& addr, int& addrLen) {
    char buffer[BUFFER_SIZE];
    int recvLen = recvfrom(socket, buffer, BUFFER_SIZE, 0, (sockaddr*)&addr, &addrLen);
    if (recvLen == SOCKET_ERROR) {
        std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
        return "";
    }
    return std::string(buffer, recvLen);
}

// Process the password file and return its contents
std::string processPasswordFile() {
    // Step 5: Load the stored hashed password from Alice's password file
    std::ifstream passwordFile("Alice/password.txt");
    if (!passwordFile.is_open()) {
        std::cerr << "Error opening password file." << std::endl;
        return "";
    }
    std::string line;
    std::getline(passwordFile, line);
    return line;
}

// Authenticate the client by verifying username and password
bool authenticateClient(const std::string& receivedPassword, const std::string& storedLine) {
    // Step 6: Extract the stored password hash from the file and verify against the received password
    size_t commaPos = storedLine.find(',');
    if (commaPos == std::string::npos) {
        std::cerr << "Invalid password file format." << std::endl;
        return false;
    }

    std::string storedHashedPassword = storedLine.substr(commaPos + 1);
    std::string receivedHashedPassword = sha1(receivedPassword);

    if (receivedHashedPassword != storedHashedPassword) {
        std::cerr << "Password verification failed." << std::endl;
        return false;
    }

    return true;
}

// Handle the client connection and secure communication
void handleClient(SOCKET clientSocket, EVP_PKEY* privateKey) {
    sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    // Step 7: Receive the first message from Bob, containing the username and nonce NB
    std::string receivedData = receiveMessage(clientSocket, clientAddr, clientAddrLen);
    if (receivedData.empty()) return;

    std::string username = receivedData.substr(0, receivedData.find(','));
    std::string nb = receivedData.substr(receivedData.find(',') + 1);

    std::cout << "Received from client: " << username << ", " << nb << std::endl;

    // Step 8: Generate a nonce NA and send it along with Alice's public key to Bob
    std::string na = generateNonce(16);
    std::string encodedNa = base64(na, Base64Operation::Encode);

    EVP_PKEY* publicKey = loadKey("Alice/public.pem", true);
    if (!publicKey) {
        std::cerr << "Failed to load public key." << std::endl;
        return;
    }

    std::string publicKeyStr = serializePublicKey(publicKey);
    EVP_PKEY_free(publicKey);

    std::string response = encodedNa + "," + publicKeyStr;
    sendMessage(clientSocket, response, clientAddr);

    // Step 9: Receive the encrypted password and session key from Bob
    std::string encryptedMessage = receiveMessage(clientSocket, clientAddr, clientAddrLen);
    if (encryptedMessage.empty()) {
        std::cerr << "Failed to receive encrypted message. Terminating client handling." << std::endl;
        return;
    }

    // Step 10: Decrypt the received message to get the password and session key
    std::string decryptedMessage = decryptRSA("Alice/private.pem", encryptedMessage);
    if (decryptedMessage.empty()) {
        std::cerr << "Failed to decrypt message. Terminating client handling." << std::endl;
        return;
    }

    decryptedMessage = sanitizeBase64(decryptedMessage);

    std::string receivedPassword = decryptedMessage.substr(0, 8);
    std::string keyK = decryptedMessage.substr(8);

    // Step 11: Authenticate Bob using the received password
    std::string storedLine = processPasswordFile();
    if (storedLine.empty()) return;

    if (!authenticateClient(receivedPassword, storedLine)) {
        sendMessage(clientSocket, "Connection Failed", clientAddr);
        return;
    }

    sendMessage(clientSocket, "Connection Okay", clientAddr);
    std::cout << "Authenticated successfully. Establishing secure session key." << std::endl;

    // Step 12: Establish the session key SSK using the shared values
    std::string ssk = sha1(keyK + nb + na).substr(0, 16);

    // Step 13: Send an acknowledgment message encrypted with the session key SSK
    std::string ackMessage = "Secure session established.";
    std::string encryptedAck = rc4(ssk, ackMessage);
    if (!encryptedAck.empty()) {
        sendMessage(clientSocket, encryptedAck, clientAddr);
    }
    else {
        std::cerr << "Error: Encryption of ACK message failed!" << std::endl;
        return;
    }

    // Step 14: Enter the secure communication loop to handle further messages from Bob
    if (!secureCommunicationLoop(clientSocket, ssk, clientAddr, clientAddrLen)) {
        std::cout << "Terminating handleClient due to session closure." << std::endl;
        return;
    }
}

// Secure communication loop with the client
bool secureCommunicationLoop(SOCKET clientSocket, const std::string& ssk, sockaddr_in& clientAddr, int& clientAddrLen) {
    bool sessionActive = true;
    bool exitReceived = false;

    while (sessionActive) {
        // Step 15: Receive and decrypt messages from Bob in the secure communication loop
        std::string encryptedClientMessage = receiveMessage(clientSocket, clientAddr, clientAddrLen);

        if (encryptedClientMessage.empty()) {
            if (exitReceived) {
                exitReceived = false;
                continue;
            }
            else {
                std::cerr << "Warning: Received an empty or invalid message. Terminating session..." << std::endl;
                break;
            }
        }

        std::string decryptedMessage = rc4(ssk, encryptedClientMessage);
        if (decryptedMessage.empty()) {
            std::cerr << "Error: Decryption failed. Terminating session..." << std::endl;
            break;
        }

        if (exitReceived) {
            std::cout << "Ignoring further message after exit command: " << decryptedMessage << std::endl;
            break;
        }

        std::cout << "Received (decrypted): " << decryptedMessage << std::endl;

        if (decryptedMessage == "exit") {
            std::cout << "Client requested to terminate the session." << std::endl;
            exitReceived = true;
            continue;
        }

        // Step 16: Encrypt and send an echo response back to Bob
        std::string response = "Echo: " + decryptedMessage;
        std::string encryptedResponse = rc4(ssk, response);

        if (encryptedResponse.empty()) {
            std::cerr << "Critical Error: Encryption failed. Terminating session..." << std::endl;
            break;
        }

        sendMessage(clientSocket, encryptedResponse, clientAddr);
    }

    std::cout << "Session terminated." << std::endl;

    return false;
}
