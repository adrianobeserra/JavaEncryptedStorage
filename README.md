# JavaEncryptedStorage - Java Client-Server System with End-to-End Encryption and Authentication
SecureFileShare is a Java-based client-server system that facilitates secure file uploads and storage on a central server. The system employs end-to-end encryption and authentication mechanisms to ensure data confidentiality and integrity during file transfers.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Introduction](#introduction)
- [Key Features](#key-features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites
- Java 11: Make sure you have Java 11 or a later version installed on your system. You can check your Java version by running the following command in the terminal:

```bash
java -version
```

If Java 11 is not installed, you can download and install it from the [official Java website](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html) or use a package manager like [SDKMAN!](https://sdkman.io/) or [Homebrew](https://brew.sh/) to install it.


## Introduction
In today's digital age, data security is paramount. SecureFileShare addresses the need for a safe file-sharing environment, where users can confidently upload, save, and retrieve their files without compromising sensitive information. This project provides a Java 11-based implementation of a client-server architecture, leveraging public and private keys for end-to-end encryption and authentication.

## Key Features
- **Client-Server Architecture:** The project follows a client-server model, allowing clients to interact with the central file server securely.
- **RSA Key Generation:** RSAKeyGen.java provides functionalities to generate public and private key pairs for encryption and decryption.
- **End-to-End Encryption:** All files transferred between the client and server are encrypted using RSA encryption, ensuring data privacy.
- **Authentication:** Users must authenticate using their credentials before accessing the system, preventing unauthorized access.
- **Utils Class:** The Utils.java file contains utility functions to support various encryption and decryption operations.

## Installation
To set up the JavaEncryptedStorage system on your local machine, follow these steps:

1. Clone the repository: `git clone (https://github.com/adrianobeserra/JavaEncryptedStorage.git`
2. Compile the Java files: `javac Client.java RSAKeyGen.java Server.java Utils.java`

## Usage
The JavaEncryptedStorage system consists of a client and a server Java program, and they must be named `Client.java` and `Server.java`, respectively. They are started by running the commands:

1. Run the server: `java Server port`
  - Replace `port` with the port number where the server should listen for client connections.

2. To run the client: `java Client host port userid filename`
  - Replace `host` with the hostname or IP address of the server.
  - Replace `port` with the port number where the server is listening.
  - Replace `userid` with the client's user ID.
  - Replace `filename` with the name of the file to be encryipted.

Ensure that you keep your private key safe, as it is crucial for decryption.

## Contributing
Contributions to JavaEncryptedStorage are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request. Follow the guidelines outlined in CONTRIBUTING.md for a smooth collaboration process.

## License
This project is licensed under the GNU General Public License v3.0 - see the [GNU General Public License v3.0](LICENSE) file for details.

