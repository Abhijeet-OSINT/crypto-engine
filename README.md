# Crypto Engine

A Java cryptographic library and interactive command-line interface supporting symmetric ciphers, asymmetric cryptosystems, cryptographic hashing/MAC, post-quantum key encapsulation envelopes, and classical ciphers. Implemented using the Java Cryptography Architecture (JCA/JCE) and Bouncy Castle.

## Features

- **Symmetric Ciphers (Encryption & Decryption):**
  - AES-GCM (128, 192, 256-bit) with AEAD authentication tag and Additional Authenticated Data (AAD) support
  - Single DES (56-bit CBC)
  - Double DES (2DES 112-bit pipeline)
  - Triple DES (3DES 168-bit EDE mode)
  - Blowfish (variable key up to 448-bit, 256-bit default)
  - Twofish (256-bit CBC)
  - IDEA (128-bit CBC)
  - RC4 (stream cipher)
  - RC5 (128-bit CBC)
  - RC6 (256-bit CBC)
- **Asymmetric Cryptosystems:**
  - RSA-OAEP: Public-key encryption and private-key decryption (2048-bit, SHA-256 / MGF1)
  - RSA-PSS: Digital signatures and signature verification (SHA-256)
  - DSA: Digital signatures and verification (2048-bit, SHA-256)
  - ECDSA: Elliptic curve digital signatures and verification (NIST P-256 / secp256r1)
  - Diffie-Hellman: Key exchange and shared secret derivation (MODP Groups 14 and 15)
  - ECDH: Elliptic curve key exchange (secp256r1)
- **Cryptographic Hashing & MAC:**
  - MD5, SHA-1, SHA-224, SHA-256, SHA-512
  - SHA3-256, SHA3-512
  - HMAC-SHA256, HMAC-SHA512
- **Post-Quantum Cryptography:**
  - ML-KEM-768 (FIPS 203) hybrid envelope combining lattice-based key encapsulation, HKDF-SHA256, and AES-256-GCM authenticated payload encryption and decryption
- **Classical Historical Ciphers:**
  - Caesar cipher (shift encryption and decryption)
  - ROT13 (self-inverse substitution)
  - Vigenere cipher (polyalphabetic encryption and decryption)
- **Diagnostics & Testing:**
  - Built-in self-tests verifying NIST test vectors, round-trip decryption consistency, IV/nonce uniqueness, and AEAD tampering detection

## Requirements

- Java 21 or later
- Maven 3.8+ (for building from source)

## Building

Compile the project and run the automated test suite:

```bash
mvn clean test
```

Package an executable JAR containing all dependencies:

```bash
mvn clean package
```

The compiled artifact is generated at:
`target/crypto-engine-1.0.0-SNAPSHOT-jar-with-dependencies.jar`

## Running the CLI

Run via Maven:

```bash
mvn exec:java
```

Or run the packaged JAR:

```bash
java -jar target/crypto-engine-1.0.0-SNAPSHOT-jar-with-dependencies.jar
```

## CLI Operation Modes

When selecting any cipher in the interactive menu, three operational modes are available:

1. **Encrypt:** Prompts for custom plaintext (or accepts defaults), generates fresh keys/IVs, and outputs the resulting ciphertext in both Hex and Base64 alongside the key material.
2. **Decrypt:** Prompts for existing ciphertext and required parameters (key, IV, AAD, or private key) to decrypt data back to UTF-8 plaintext.
3. **Automated Demo:** Executes an end-to-end round-trip test (key generation -> encryption -> decryption -> verification) displaying all intermediate values.

### Decryption Walkthroughs

#### 1. AES-256-GCM Decryption
AES-GCM is an authenticated encryption scheme. Decryption requires the ciphertext (which includes the 128-bit authentication tag appended at the end), the 256-bit key, and the 96-bit initialization vector (IV).

1. Launch the CLI and select `2. Symmetric Ciphers` -> `1. AES-256-GCM`.
2. Choose option `2` (Decrypt).
3. Provide the required inputs:
   - **Ciphertext:** Hex or Base64 encoded ciphertext string.
   - **Key:** 64-character hexadecimal string representing the 256-bit key.
   - **IV:** 24-character hexadecimal string representing the 12-byte IV.
   - **AAD:** Additional Authenticated Data text used during encryption (optional, leave blank if none).
4. The engine verifies the authentication tag and prints the recovered plaintext. If the ciphertext or AAD has been altered, an authentication tag verification error is raised.

#### 2. Symmetric Block Ciphers (DES, 3DES, Blowfish, Twofish, IDEA, RC5, RC6)
All block ciphers operate in CBC mode with PKCS5/PKCS7 padding:
1. Select the desired algorithm from the Symmetric menu.
2. Choose option `2` (Decrypt).
3. Enter the ciphertext in Hex, the secret key in Hex (sized according to the algorithm), and the initialization vector in Hex.

#### 3. RSA-OAEP Decryption
1. Select `3. Asymmetric Cryptography` -> `1. RSA-OAEP`.
2. Choose option `2` (Decrypt).
3. Enter the ciphertext in Hex and the recipient's private key in PKCS#8 Base64 format.
4. The engine decodes the private key, unpads the OAEP envelope using SHA-256/MGF1, and outputs the decrypted message.

#### 4. Post-Quantum ML-KEM-768 Hybrid Envelope Decryption
1. Select `5. Post-Quantum Cryptography`.
2. Choose option `2` (Decrypt).
3. Enter the binary wire-format envelope in Base64 format.
4. Enter the recipient's ML-KEM-768 private key in PKCS#8 Base64 format.
5. The engine parses the wire format, decapsulates the shared secret using ML-KEM-768, derives the AES-256-GCM symmetric key via HKDF-SHA256, and decrypts the authenticated payload.

#### 5. Classical Ciphers
- **Caesar:** Enter ciphertext and the integer shift value (0-25) to reverse the substitution.
- **ROT13:** Running ROT13 on the ciphertext reverses the 13-character rotation.
- **Vigenere:** Enter ciphertext and the keyword to reverse the polyalphabetic shift.

## Programmatic Java API

The library provides static methods across dedicated service classes for programmatic use.

### AES-256-GCM Example

```java
import com.securecrypto.engine.symmetric.AesService;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

// Generate key and IV
SecretKey key = AesService.generateAesKey(256);
byte[] iv = AesService.generateIv();
byte[] aad = "HEADER".getBytes(StandardCharsets.UTF_8);

// Encrypt
byte[] plaintext = "Confidential message".getBytes(StandardCharsets.UTF_8);
byte[] ciphertext = AesService.encryptGcm(plaintext, key, iv, aad);

// Decrypt
byte[] decrypted = AesService.decryptGcm(ciphertext, key, iv, aad);
String result = new String(decrypted, StandardCharsets.UTF_8);
```

### RSA-OAEP Example

```java
import com.securecrypto.engine.asymmetric.RsaService;
import java.security.KeyPair;
import java.nio.charset.StandardCharsets;

KeyPair keyPair = RsaService.generateRsaKeyPair(2048);

// Encrypt with public key
byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);
byte[] ciphertext = RsaService.encryptOaep(plaintext, keyPair.getPublic());

// Decrypt with private key
byte[] decrypted = RsaService.decryptOaep(ciphertext, keyPair.getPrivate());
String result = new String(decrypted, StandardCharsets.UTF_8);
```

### Post-Quantum Hybrid Envelope Example

```java
import com.securecrypto.engine.pqc.HybridPqcService;
import java.security.KeyPair;
import java.nio.charset.StandardCharsets;

KeyPair recipientKeys = HybridPqcService.generateMlKem768KeyPair();
byte[] payload = "Post-quantum data".getBytes(StandardCharsets.UTF_8);
byte[] aad = "RECIPIENT-ID".getBytes(StandardCharsets.UTF_8);

// Encrypt to wire format
byte[] wireFormat = HybridPqcService.encryptHybridEnvelope(payload, recipientKeys.getPublic(), aad);

// Decrypt using recipient private key
byte[] decrypted = HybridPqcService.decryptHybridEnvelope(wireFormat, recipientKeys.getPrivate());
String result = new String(decrypted, StandardCharsets.UTF_8);
```

### Classical Ciphers Example

```java
import com.securecrypto.engine.classical.ClassicalCiphers;

// Caesar
String caesarEnc = ClassicalCiphers.encryptCaesar("HELLO", 3); // "KHOOR"
String caesarDec = ClassicalCiphers.decryptCaesar("KHOOR", 3); // "HELLO"

// Vigenere
String vigEnc = ClassicalCiphers.encryptVigenere("HELLO", "KEY");
String vigDec = ClassicalCiphers.decryptVigenere(vigEnc, "KEY"); // "HELLO"
```

## Project Structure

```text
crypto-engine/
├── pom.xml
└── src/
    ├── main/java/com/securecrypto/engine/
    │   ├── CryptoApplication.java              # Interactive CLI with Encrypt/Decrypt/Demo submenus
    │   ├── core/                               # Diagnostics, Hex/Base64 utils, KeyZeroizer
    │   ├── symmetric/                          # AES, DES, 2DES, 3DES, Blowfish, Twofish, IDEA, RC4/5/6
    │   ├── asymmetric/                         # RSA (OAEP/PSS), DSA, ECDSA, DH, ECDH
    │   ├── hashing/                            # Hash functions & HMAC
    │   ├── pqc/                                # ML-KEM-768 hybrid envelope service
    │   └── classical/                          # Caesar, ROT13, Vigenère
    └── test/java/com/securecrypto/engine/
        └── ComprehensiveCryptoTest.java        # 31 unit tests covering all ciphers
```

## Development Team

Developed by:
- **Team Lead:** Abhijeet
- **Team Mates:**
  - Abhay Mathur
  - Aarush Sharma
  - Mayanck
  - Subham Kumar Pandey

