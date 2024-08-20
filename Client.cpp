#include "../Crypt Func/crypt_func.h"
#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <thread>
#include <chrono>
#include <fstream>
#include <openssl/rand.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#define SOCKET int
#define INVALID_SOCKET -1
#endif

#undef max

constexpr int CLIENT_PORT = 3333;
constexpr int HOST_PORT = 5555;
constexpr int BUFFER_SIZE = 1024;

// Function Declarations
bool initializeWinsock(WSADATA& wsaData);  // Step 1: Initialize Winsock for network communication
SOCKET createSocket();  // Step 2: Create the client socket
void closeSocket(SOCKET& socket);  // Helper: Close the socket to release resources
bool setupAddress(sockaddr_in& serverAddr);  // Step 3: Set up the server address for communication
void authenticateAndCommunicate(SOCKET serverSocket, sockaddr_in& serverAddr);  // Step 4: Handle the communication with the server, including authentication and secure messaging
bool sendToServer(SOCKET serverSocket, const std::string& message, const sockaddr_in& serverAddr);  // Helper: Send a message to the server
std::string receiveFromServer(SOCKET serverSocket);  // Helper: Receive a message from the server
std::string generateSessionKey(const std::string& encodedK, const std::string& nb, const std::string& na);  // Step 7: Generate the session key using K, Nb, and Na, and SHA-1
bool validateInput(std::string& input);  // Helper: Validate user input, checking for empty strings or stream errors
void interactiveMessagingLoop(SOCKET serverSocket, const std::string& ssk, const sockaddr_in& serverAddr);  // Step 8: Enter the interactive messaging loop for secure communication with the server

// Main function to initiate the client communication
int main() {
    WSADATA wsaData;
    if (!initializeWinsock(wsaData)) return 1;  // Step 1: Initialize Winsock

    SOCKET clientSocket = createSocket();  // Step 2: Create the client socket
    if (clientSocket == INVALID_SOCKET) return 1;

    sockaddr_in serverAddr;
    if (!setupAddress(serverAddr)) return 1;  // Step 3: Set up the server address

    try {
        authenticateAndCommunicate(clientSocket, serverAddr);  // Step 4: Handle authentication and secure communication with the server
    }
    catch (const std::exception& ex) {
        std::cerr << "An error occurred: " << ex.what() << std::endl;
    }

    closeSocket(clientSocket);  // Step 9: Close the socket and clean up resources
    WSACleanup();
    std::cout << "Client exited cleanly." << std::endl;
    return 0;
}

// Initialize Winsock for network communication
bool initializeWinsock(WSADATA& wsaData) {
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return false;
    }
    return true;
}

// Create the client socket
SOCKET createSocket() {
    SOCKET socketDesc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // Step 2: Create a UDP socket
    if (socketDesc == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        WSACleanup();
    }
    return socketDesc;
}

// Close socket to release resources
void closeSocket(SOCKET& socket) {
    if (socket != INVALID_SOCKET) {
        closesocket(socket);  // Step 9: Close the socket to release resources
        socket = INVALID_SOCKET;
    }
}

// Setup the server address for communication
bool setupAddress(sockaddr_in& serverAddr) {
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(HOST_PORT);  // Step 3: Set the server port
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) <= 0) {  // Step 3: Set the server IP address
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return false;
    }
    return true;
}

// Handle the communication with the server, including authentication and secure messaging
void authenticateAndCommunicate(SOCKET serverSocket, sockaddr_in& serverAddr) {
    while (true) {
        std::string username, password;
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;

        // Step 5: Generate and encode nonce (Nb)
        std::string nb = generateNonce(16);
        std::string request = username + "," + nb;

        // Step 6: Send the username and encoded nonce (Nb) to the server
        if (!sendToServer(serverSocket, request, serverAddr)) return;

        // Step 6: Receive the nonce (Na) and the server's public key
        std::string response = receiveFromServer(serverSocket);
        if (response.empty()) return;

        // Step 6: Extract Na and Alice's public key from the response
        std::string na = response.substr(0, response.find(','));
        std::string decodedNa = base64(na, Base64Operation::Decode);
        std::string alicePublicKey = response.substr(response.find(',') + 1);

        // Step 6: Verify the public key fingerprint
        if (!verifyFingerprint(alicePublicKey)) {
            std::cerr << "Public key fingerprint does not match. Terminating connection." << std::endl;
            return;
        }

        // Step 7: Generate the session key (K)
        unsigned char keyK[16];
        if (!RAND_bytes(keyK, sizeof(keyK))) {
            std::cerr << "Failed to generate random bytes" << std::endl;
            return;
        }
        std::string encodedK = vectorToBase64({ keyK, keyK + sizeof(keyK) }, Base64Operation::Encode);

        // Step 7: Encrypt password and session key (K) with the server's public key
        std::string encryptedData = encryptRSA("Alice/public.pem", password + encodedK);
        if (!sendToServer(serverSocket, encryptedData, serverAddr)) return;

        // Step 8: Receive the connection status from the server
        std::string connectionStatus = receiveFromServer(serverSocket);
        if (connectionStatus != "Connection Okay") {
            std::cout << "Connection Failed: Invalid Password. Please try again..." << std::endl;
            continue; // Retry the loop for a new login attempt
        }

        std::cout << "Authenticated successfully. Establishing secure session key." << std::endl;

        // Step 7: Generate the session key (SSK)
        std::string ssk = generateSessionKey(encodedK, nb, decodedNa);

        // Step 8: Send a test message using the session key (SSK)
        std::string testMessage = "Hello Alice, this is Bob!";
        if (!sendToServer(serverSocket, rc4(ssk, testMessage), serverAddr)) return;

        // Step 8: Receive and decrypt the server's response
        std::string encryptedResponse = receiveFromServer(serverSocket);
        if (encryptedResponse.empty()) return;

        std::cout << "Received from server: " << rc4(ssk, encryptedResponse) << std::endl;

        // Step 8: Start the interactive messaging loop
        interactiveMessagingLoop(serverSocket, ssk, serverAddr);
        break; // Exit loop after successful communication
    }
}

// Generate the session key (SSK) using K, Nb, and Na, and SHA-1
std::string generateSessionKey(const std::string& encodedK, const std::string& nb, const std::string& na) {
    std::string combined = encodedK + nb + na;
    return sha1(combined).substr(0, 16);  // Step 7: Generate the secure session key (SSK) using SHA-1
}

// Send a message to the server
bool sendToServer(SOCKET serverSocket, const std::string& message, const sockaddr_in& serverAddr) {
    if (sendto(serverSocket, message.c_str(), message.size(), 0, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Send failed: " << WSAGetLastError() << std::endl;
        return false;
    }
    return true;
}

// Receive a message from the server
std::string receiveFromServer(SOCKET serverSocket) {
    char buffer[BUFFER_SIZE];
    int recvLen = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0, nullptr, nullptr);
    if (recvLen == SOCKET_ERROR) {
        std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
        return "";
    }
    return std::string(buffer, recvLen);
}

// Validate user input, checking for empty strings or stream errors
bool validateInput(std::string& input) {
    std::cin.clear();
    std::cin.sync();
    std::getline(std::cin, input);

    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cerr << "Error: Stream error detected! Please try again." << std::endl;
        return false;
    }

    if (input.empty()) {
        std::cerr << "Error: Input is empty! Please enter a valid value." << std::endl;
        return false;
    }

    return true;
}

// Interactive messaging loop for secure communication with the server
void interactiveMessagingLoop(SOCKET serverSocket, const std::string& ssk, const sockaddr_in& serverAddr) {
    // Step 8: Clean the input stream before entering the loop.
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    while (true) {
        // Step 8: Receive the server's encrypted response
        std::string encryptedResponse = receiveFromServer(serverSocket);
        if (encryptedResponse.empty()) {
            std::cerr << "Error: Received an empty response from the server! Terminating the session." << std::endl;
            break;
        }

        // Step 8: Decrypt the server's response using the session key (SSK)
        std::string decryptedResponse = rc4(ssk, encryptedResponse);
        std::cout << "Received from server (decrypted): " << decryptedResponse << std::endl;

        std::string message;
        std::cout << "Enter a message to send (type 'exit' to quit): ";

        if (!validateInput(message)) continue;

        // Step 8: Check if the user wants to exit
        if (message == "exit") {
            std::cout << "Exiting the session..." << std::endl;

            // Notify the server about the exit
            std::string encryptedExitMessage = rc4(ssk, "exit");
            sendToServer(serverSocket, encryptedExitMessage, serverAddr);
            if (!sendToServer(serverSocket, encryptedExitMessage, serverAddr)) {
                std::cerr << "Error: Failed to send exit notification to server!" << std::endl;
            }
            break; // Exit the loop
        }

        // Step 8: Encrypt the message with the session key (SSK) and send it to the server
        std::string encryptedMessage = rc4(ssk, message);
        if (!sendToServer(serverSocket, encryptedMessage, serverAddr)) {
            std::cerr << "Error: Failed to send message to server! Terminating the session." << std::endl;
            break;
        }

        // Step 8: Add a small delay to ensure message processing
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
