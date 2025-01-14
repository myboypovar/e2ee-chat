# End-to-End Encrypted Chat Application

A secure, end-to-end encrypted chat application implemented in Python. This project demonstrates the implementation of modern cryptographic protocols for secure communication between multiple clients through a central server.

## Features

- **End-to-End Encryption**: Uses X25519 for key exchange and AES-GCM for message encryption
- **RSA Signatures**: Ensures message authenticity and integrity
- **Phone Number Authentication**: OTP-based user verification
- **Asynchronous Communication**: Handles multiple clients simultaneously
- **Offline Message Support**: Stores encrypted messages for offline users
- **SQLite Database**: Persistent storage for user data and messages

## Security Features

- **Perfect Forward Secrecy**: Achieved through Diffie-Hellman key exchange
- **Message Integrity**: RSA signatures prevent message tampering
- **Secure Key Storage**: Private keys can be password-protected
- **OTP Verification**: Time-based one-time passwords for registration
- **Server-Side Key Verification**: Server signs client public keys
- **Encrypted Message Queue**: Messages are stored encrypted for offline recipients

## Technical Architecture

### Components

1. **Client (`client.py`)**
   - Handles user authentication and registration
   - Manages encrypted communication
   - Implements threading for simultaneous send/receive operations
   - Maintains secure key storage

2. **Server (`server.py`)**
   - Manages client connections using selectors
   - Routes encrypted messages between clients
   - Handles client authentication and key distribution
   - Implements message queuing for offline clients

3. **Database (`database.py`)**
   - SQLite-based persistent storage
   - Stores client information and encrypted messages
   - Manages user verification states
   - Handles message queuing

4. **Cryptography (`crypto.py`)**
   - Implements X25519 for key exchange
   - Uses HKDF for key derivation
   - Handles RSA signatures
   - Manages AES-GCM encryption/decryption

5. **Protocol (`protocol.py`)**
   - Defines communication protocol between client and server
   - Implements message serialization/deserialization
   - Handles various types of payloads
   - Manages protocol versioning

## Installation

1. Clone the repository:
```bash
git clone https://github.com/myboypovar/e2ee-chat.git
cd e2ee-chat
```

2. Install required packages:
```bash
pip install cryptography
```

## Usage

1. Start the server:
```bash
python server.py
```

2. Run a client:
```bash
python client.py
```

3. Register with a phone number and verify with the OTP
4. Start chatting securely with other users

## Protocol Specification

The application uses a custom protocol with the following request types:

- Registration and Authentication
  - REQUEST_REGISTER (825)
  - REQUEST_OTP (831)
  - REQUEST_LOGIN (827)

- Key Exchange
  - REQUEST_SEND_PUBLIC_KEYS (826)
  - REQUEST_RECIPIENT_KEYS (828)
  - REQUEST_SENDER_KEYS (832)

- Messaging
  - REQUEST_MESSAGE (829)
  - REQUEST_MESSAGE_RECEIVED (830)

Each message includes:
- Phone number
- Version number
- Operation code
- Payload size
- Payload data


The following response messages from the server:

- Registration and Authentication
  - RESPONSE_REGISTRATION (1600)
  - REQUEST_OTP_OK (1604)
  - REQUEST_LOGIN (1605)

- Key Exchange
  - RESPONSE_KEYS_SET (1602)
  - RESPONSE_RECIPIENT_KEYS (1603)
  - RESPONSE_SENDER_KEYS (1610)

- Messaging
  - RESPONSE_MESSAGE (1608)
  - RESPONSE_MESSAGE_SENT (1609)
  - RESPONSE_LISTENING (1611)
 
- Errors
  - RESPONSE_REGISTRATION_FAILED (1601)
  - RESPONSE_LOGIN_FAILED (1606)
  - RESPONSE_ERROR (1607)

Each message includes:
- Version number
- Operation code
- Payload size
- Payload data

## Security Considerations

- Private keys should be properly secured
- Server's public key must be distributed securely
- OTP should be sent through a secure channel in production
- Database should be properly secured in production
- Connection should use TLS in production

## Development

### Project Structure
```
e2ee-chat/
└── Server/
    └── server.py
    └── connection.py
    └── database.py
    └── RSA.py
└── Client/
    └── client.py
    └── crypto.py
└── Utils/
    └── protocol.py
```

### Future Improvements

1. Add support for group chats
2. Implement message persistence
3. Add file transfer capabilities
4. Implement contact list functionality
5. Add support for message deletion
6. Implement read receipts
7. Add support for voice/video calls

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Cryptography.io](https://cryptography.io/) for the cryptographic primitives
- [SQLite](https://www.sqlite.org/) for the database engine
- [Python Socket Programming](https://docs.python.org/3/library/socket.html) documentation
