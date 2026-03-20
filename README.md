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

## SmartyPants

SmartyPants converts ASCII punctuation characters into "smart" typographic punctuation HTML entities. For example:

|                  | ASCII                           | HTML                          |
| ---------------- | ------------------------------- | ----------------------------- |
| Single backticks | `'Isn't this fun?'`             | 'Isn't this fun?'             |
| Quotes           | `"Isn't this fun?"`             | "Isn't this fun?"             |
| Dashes           | `-- is en-dash, --- is em-dash` | -- is en-dash, --- is em-dash |

And this will produce a flow chart:

```mermaid
graph LR
A[Square Rect] -- Link text --> B((Circle))
A --> C(Round Rect)
B --> D{Rhombus}
C --> D
```
