# qpost

Post quantum cryptography file transfer command line tool.



# Architecture

One way file transfer protocol. Receiver runs the server source code and sender runs the client source code.

Uses CRYSTALS-Kyber key encapsulation, which has been selected by NIST as one of the standard algorithms for post quantum public-key encryption.



# Handshake

```mermaid
sequenceDiagram
Client ->> Server: ClientHello: nonce, supported alogrithms
Server ->> Client: ServerHello: chosen algorithm, nonce, x25519 public key, kyber public key

Client ->> Server: ClientKeyShare: x25519 public key, encapsulated kyber ciphertext

Note right of Server: Both sides compute shared secret

Server ->> Client: ServerFinished: HMAC of handshake messages
Client ->> Server: ClientFinished: HMAC of handshake messages

Client ->> Server: FileData
Client ->> Server: CloseConnection
```



# Instructions for use

Clone the repository:
`git clone https://github.com/biokemisti/qpost`

Initialize CMake:
`cmake`

Build the project with:
`make`



# Dependencies
In order to successfully build the tool, the following dependencies need to be installed:


| Library          | Tested version                  |
| ---------------- | ------------------------------- |
| libsodium        | 1.0.21                          |
| liboqs           | 0.12.0                          |



And this will produce a flow chart:

```mermaid
graph LR
A[Square Rect] -- Link text --> B((Circle))
A --> C(Round Rect)
B --> D{Rhombus}
C --> D
```
