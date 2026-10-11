# Cryptographic Engineering Suite (JDK 21+)

A comprehensive, modular, production-ready Cryptographic Engineering Suite written in Java 21+.

## Supported Algorithms
- **Symmetric Ciphers:** AES-256-GCM (AEAD with AAD), DES, Double-DES (2DES), Triple-DES (3DES), Blowfish, Twofish, IDEA, RC4, RC5, RC6.
- **Asymmetric Cryptography:** RSA-OAEP, RSA-PSS, DSA (FIPS 186-4), ECDSA (secp256r1), Diffie-Hellman (RFC 3526 Groups 14 & 15), ECDH (secp256r1).
- **Hash Functions & HMAC:** MD5, SHA-1, SHA-224, SHA-256, SHA-512, SHA3-256, SHA3-512, HmacSHA256, HmacSHA512.
- **Post-Quantum Cryptography:** FIPS 203 ML-KEM-768 key encapsulation + HKDF-SHA256 + AES-256-GCM + AAD hybrid framing.
- **Classical Historical Ciphers:** Caesar, ROT13, Vigenère.
- **Automated Diagnostics:** Self-test checks verifying KAT test vectors, nonce uniqueness, key zeroization, and AEAD bad-tag tamper detection.

---

## 🚀 How to Run on Any Computer

### Prerequisite
- **Java 21 (JDK 21+)** installed on the target machine.

---

### Option A: Run the Pre-Built Executable JAR (Easiest — No Setup Required)
Open terminal / command prompt in the project root folder and run:

```bash
# On Windows / macOS / Linux:
java -jar target/crypto-engine-1.0.0-SNAPSHOT-jar-with-dependencies.jar
```

---

### Option B: Build & Test Using Maven
If Apache Maven is installed:

1. **Run 31 Automated Tests & Diagnostic Suite:**
   ```bash
   mvn test
   ```

2. **Launch Interactive Terminal CLI:**
   ```bash
   mvn exec:java
   ```

3. **Re-package Standalone Executable JAR:**
   ```bash
   mvn clean package
   ```

---

## Project Layout

```
crypto-engine/
├── pom.xml
├── README.md
└── src/
    ├── main/java/com/securecrypto/engine/
    │   ├── CryptoApplication.java              # Interactive Terminal CLI
    │   ├── core/                               # Diagnostics, HexUtils, KeyZeroizer
    │   ├── symmetric/                          # AES, DES, 2DES, 3DES, Blowfish, Twofish, IDEA, RC4/5/6
    │   ├── asymmetric/                         # RSA, DSA, ECDSA, DH, ECDH
    │   ├── hashing/                            # Hashes & HMAC
    │   ├── pqc/                                # ML-KEM-768 Hybrid Envelope
    │   └── classical/                          # Caesar, ROT13, Vigenère
    └── test/java/com/securecrypto/engine/
        └── ComprehensiveCryptoTest.java        # 31 Regression & Anti-Tamper Tests
```
