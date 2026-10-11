# Crypto Engine

A Java library and command-line utility implementing symmetric, asymmetric, hash/MAC, post-quantum, and classical ciphers using standard JCA/JCE and Bouncy Castle.

## Features

- **Symmetric Ciphers:** AES-GCM (128/192/256), DES, 2DES, 3DES, Blowfish, Twofish, IDEA, RC4, RC5, RC6
- **Asymmetric:** RSA-OAEP, RSA-PSS, DSA, ECDSA (secp256r1), Diffie-Hellman (MODP Groups 14/15), ECDH
- **Hashing & MAC:** MD5, SHA-1, SHA-224, SHA-256, SHA-512, SHA3-256, SHA3-512, HMAC (SHA-256, SHA-512)
- **Post-Quantum:** ML-KEM-768 (FIPS 203) key encapsulation combined with HKDF-SHA256 and AES-256-GCM authenticated envelope
- **Classical:** Caesar, ROT13, Vigenère
- **Diagnostics:** Built-in self-tests for known test vectors, nonce uniqueness, and AEAD tamper detection

## Requirements

- Java 21 or later
- Maven 3.8+ (for building from source)

## Building

To compile the project and run the test suite:

```bash
mvn clean test
```

To build an executable JAR with all dependencies included:

```bash
mvn clean package
```

The resulting JAR will be created under `target/crypto-engine-1.0.0-SNAPSHOT-jar-with-dependencies.jar`.

## Running

Run the interactive CLI:

```bash
mvn exec:java
```

Or run the packaged JAR directly:

```bash
java -jar target/crypto-engine-1.0.0-SNAPSHOT-jar-with-dependencies.jar
```

## Structure

```text
crypto-engine/
├── pom.xml
└── src/
    ├── main/java/com/securecrypto/engine/
    │   ├── CryptoApplication.java              # CLI entry point
    │   ├── core/                               # Diagnostics, Hex/Base64 utils, KeyZeroizer
    │   ├── symmetric/                          # AES, DES, Blowfish, Twofish, IDEA, RC4/5/6
    │   ├── asymmetric/                         # RSA, DSA, ECDSA, DH, ECDH
    │   ├── hashing/                            # Hash functions & HMAC
    │   ├── pqc/                                # ML-KEM-768 hybrid envelope
    │   └── classical/                          # Caesar, ROT13, Vigenère
    └── test/java/com/securecrypto/engine/
        └── ComprehensiveCryptoTest.java        # Unit tests
```
