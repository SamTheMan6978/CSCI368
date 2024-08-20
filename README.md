
# Secure Communication Protocol

This repository contains the implementation of a secure communication protocol between two entities, Alice and Bob, using UDP. The protocol ensures secure message exchange through RSA encryption, RC4 stream cipher, and SHA-1 hashing. This project is designed as part of a network security course and demonstrates key concepts such as secure key exchange, authentication, and message confidentiality.

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Compilation Instructions](#compilation-instructions)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features
- **Key Generation (KeyGen):** Generates RSA key pairs for Alice, stores them in PEM format, and computes the fingerprint for verification.
- **Alice (Host):** Acts as the server that authenticates Bob using RSA and SHA-1, establishes a secure session, and engages in encrypted communication.
- **Bob (Client):** Acts as the client that authenticates with Alice, securely exchanges keys, and communicates over an encrypted channel.

## Project Structure

```
├── crypt_func.cpp      # Implementation of cryptographic functions
├── crypt_func.h        # Header file for cryptographic functions
├── Host.cpp            # Implementation of Alice's server-side logic
├── Client.cpp          # Implementation of Bob's client-side logic
├── key_gen.cpp         # Utility for generating RSA key pairs
└── build_instructions.txt  # Detailed build instructions for various platforms
```

## File Descriptions
- **`Host.cpp`:** Contains the implementation of Alice's server-side logic, including authentication, key exchange, and secure communication.
- **`Client.cpp`:** Contains the implementation of Bob's client-side logic, including secure authentication and message exchange.
- **`key_gen.cpp`:** A utility to generate RSA key pairs, storing them in PEM format, and creating a fingerprint for public key verification.
- **`crypt_func.cpp` & `crypt_func.h`:** These files provide the cryptographic functions required for RSA encryption/decryption, RC4 stream cipher, SHA-1 hashing, and Base64 encoding/decoding.

## Dependencies
- **OpenSSL:** Used for cryptographic operations including RSA, RC4, and SHA-1. Make sure OpenSSL is installed and accessible via your system’s PATH.
- **GCC/Clang:** For compiling the project on Linux/macOS.
- **MinGW:** For compiling the project on Windows.

## Installation

### 1. OpenSSL Installation
- **Linux/macOS:**
  ```bash
  sudo apt-get install libssl-dev   # For Linux
  brew install openssl              # For macOS
  ```

- **Windows:**
  - Download and install OpenSSL from [here](https://slproweb.com/products/Win32OpenSSL.html).
  - Add the OpenSSL `bin` directory to your system PATH.

### 2. Compiler Installation
- **Linux:** GCC is typically pre-installed. If not, install it using:
  ```bash
  sudo apt-get install build-essential
  ```

- **macOS:** Install Xcode command line tools:
  ```bash
  xcode-select --install
  ```

- **Windows:** Install MinGW and ensure it's added to your system PATH.

## Compilation Instructions

### Windows (Command-Line Using MinGW)
1. Open the Command Prompt or PowerShell.
2. Navigate to the directory containing your source files.
3. Compile the project using the following commands:
   ```bash
   g++ -o KeyGen key_gen.cpp crypt_func.cpp -lssl -lcrypto -lws2_32 -lwsock32
   g++ -o Alice Host.cpp crypt_func.cpp -lssl -lcrypto -lws2_32 -lwsock32
   g++ -o Bob Client.cpp crypt_func.cpp -lssl -lcrypto -lws2_32 -lwsock32
   ```
4. Run the executables in the following order:
   - `KeyGen.exe` -> `Alice.exe` -> `Bob.exe`

### Linux (GCC)
1. Open a terminal and navigate to the directory containing your source files.
2. Compile the executables using the following commands:
   ```bash
   g++ -o KeyGen key_gen.cpp crypt_func.cpp -lssl -lcrypto
   g++ -o Alice Host.cpp crypt_func.cpp -lssl -lcrypto
   g++ -o Bob Client.cpp crypt_func.cpp -lssl -lcrypto
   ```
3. Run the compiled binaries in the following order:
   ```bash
   ./KeyGen
   ./Alice
   ./Bob
   ```

### macOS (Clang)
1. Open a terminal and navigate to the directory containing your source files.
2. Compile the executables using the following commands:
   ```bash
   clang++ -o KeyGen key_gen.cpp crypt_func.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
   clang++ -o Alice Host.cpp crypt_func.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
   clang++ -o Bob Client.cpp crypt_func.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
   ```
3. Run the compiled binaries in the following order:
   ```bash
   ./KeyGen
   ./Alice
   ./Bob
   ```

## Usage

### Step 1: Generate RSA Keys
Run the `KeyGen` executable to generate RSA key pairs for Alice:
```bash
./KeyGen
```
This will create the necessary RSA key pairs and store them in the appropriate files.

### Step 2: Start the Server (Alice)
Run the `Alice` executable to start the server:
```bash
./Alice
```
Alice will listen for incoming connections from Bob.

### Step 3: Start the Client (Bob)
Run the `Bob` executable to start the client:
```bash
./Bob
```
Bob will attempt to authenticate with Alice and establish a secure communication channel.

## Contributing
If you'd like to contribute to this project, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
For any questions or contributions, please open an issue on this repository or contact the repository maintainer.
