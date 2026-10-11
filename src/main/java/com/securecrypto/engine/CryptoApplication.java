package com.securecrypto.engine;

import com.securecrypto.engine.asymmetric.DigitalSignatureService;
import com.securecrypto.engine.asymmetric.KeyAgreementService;
import com.securecrypto.engine.asymmetric.RsaService;
import com.securecrypto.engine.classical.ClassicalCiphers;
import com.securecrypto.engine.core.CryptoEngineDiagnostics;
import com.securecrypto.engine.core.CryptoEngineException;
import com.securecrypto.engine.core.HexUtils;
import com.securecrypto.engine.hashing.HashHmacService;
import com.securecrypto.engine.pqc.HybridPqcService;
import com.securecrypto.engine.symmetric.AesService;
import com.securecrypto.engine.symmetric.BlockCiphers;
import com.securecrypto.engine.symmetric.DesSuite;
import com.securecrypto.engine.symmetric.RivestCiphers;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;

/**
 * Interactive Terminal CLI Application for the Cryptographic Suite.
 * Features guided menu choices, input validation, pre-populated sample vectors,
 * and robust exception handling.
 */
public class CryptoApplication {

    private static final Scanner SCANNER = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("================================================================================");
        System.out.println("               COMPREHENSIVE JAVA CRYPTOGRAPHIC ENGINEERING SUITE               ");
        System.out.println("                              (JDK 21+ / FIPS 203 PQC)                         ");
        System.out.println("================================================================================");

        // Run startup diagnostics automatically
        CryptoEngineDiagnostics.runAllDiagnostics();

        boolean running = true;
        while (running) {
            printMainMenu();
            String choice = SCANNER.nextLine().trim();
            try {
                switch (choice) {
                    case "1" -> CryptoEngineDiagnostics.runAllDiagnostics();
                    case "2" -> handleSymmetricMenu();
                    case "3" -> handleAsymmetricMenu();
                    case "4" -> handleHashHmacMenu();
                    case "5" -> handleHybridPqcMenu();
                    case "6" -> handleClassicalMenu();
                    case "0" -> {
                        System.out.println("\nExiting Cryptographic Suite. Goodbye!");
                        running = false;
                    }
                    default -> System.out.println("\n[!] Invalid choice. Please select an option from the menu.");
                }
            } catch (CryptoEngineException e) {
                System.out.println("\n[CRYPTO ERROR] " + e.getMessage());
            } catch (Exception e) {
                System.out.println("\n[UNEXPECTED ERROR] " + e.getMessage());
            }
        }
    }

    private static void printMainMenu() {
        System.out.println("\n--- MAIN MENU ---");
        System.out.println("1. Run Self-Diagnostic Health Checks");
        System.out.println("2. Symmetric Ciphers (AES-GCM, DES, 2DES, 3DES, Blowfish, Twofish, IDEA, RC4/5/6)");
        System.out.println("3. Asymmetric Cryptography (RSA-OAEP, RSA-PSS, DSA, ECDSA, DH, ECDH)");
        System.out.println("4. Cryptographic Hashing & HMAC (MD5, SHA-1, SHA-2, SHA-3, HMAC)");
        System.out.println("5. Post-Quantum Cryptography (ML-KEM-768 Hybrid Envelope)");
        System.out.println("6. Classical Historical Ciphers (Caesar, ROT13, Vigenère)");
        System.out.println("0. Exit");
        System.out.print("Select choice: ");
    }

    private static void handleSymmetricMenu() {
        System.out.println("\n--- SYMMETRIC CIPHERS ---");
        System.out.println("1. AES-256-GCM (AEAD)");
        System.out.println("2. DES (Single 56-bit)");
        System.out.println("3. Double DES (2DES)");
        System.out.println("4. Triple DES (3DES)");
        System.out.println("5. Blowfish (256-bit)");
        System.out.println("6. Twofish (256-bit)");
        System.out.println("7. IDEA (128-bit)");
        System.out.println("8. RC4 Stream Cipher");
        System.out.println("9. RC5 Block Cipher");
        System.out.println("10. RC6 Block Cipher");
        System.out.print("Choice: ");

        String choice = SCANNER.nextLine().trim();
        String text = promptDefault("Enter plaintext message", "Symmetric Encryption Payload");

        byte[] input = text.getBytes(StandardCharsets.UTF_8);

        switch (choice) {
            case "1" -> {
                SecretKey key = AesService.generateAesKey(256);
                byte[] iv = AesService.generateIv();
                byte[] aad = "HEADER-METADATA".getBytes(StandardCharsets.UTF_8);

                byte[] ct = AesService.encryptGcm(input, key, iv, aad);
                byte[] pt = AesService.decryptGcm(ct, key, iv, aad);

                System.out.println("Key (Hex)       : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex)        : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "2" -> {
                SecretKey key = DesSuite.generateDesKey();
                byte[] iv = DesSuite.generateIv8();
                byte[] ct = DesSuite.encryptDes(input, key, iv);
                byte[] pt = DesSuite.decryptDes(ct, key, iv);

                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "3" -> {
                DesSuite.DoubleDesKeys keys = DesSuite.generate2DesKeys();
                byte[] iv1 = DesSuite.generateIv8();
                byte[] iv2 = DesSuite.generateIv8();
                byte[] ct = DesSuite.encrypt2Des(input, keys.key1, iv1, keys.key2, iv2);
                byte[] pt = DesSuite.decrypt2Des(ct, keys.key1, iv1, keys.key2, iv2);

                System.out.println("2DES Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text       : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "4" -> {
                SecretKey key = DesSuite.generate3DesKey();
                byte[] iv = DesSuite.generateIv8();
                byte[] ct = DesSuite.encrypt3Des(input, key, iv);
                byte[] pt = DesSuite.decrypt3Des(ct, key, iv);

                System.out.println("3DES Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text       : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "5" -> {
                SecretKey key = BlockCiphers.generateBlowfishKey(256);
                byte[] iv = BlockCiphers.generateIv8();
                byte[] ct = BlockCiphers.encryptBlowfish(input, key, iv);
                byte[] pt = BlockCiphers.decryptBlowfish(ct, key, iv);

                System.out.println("Blowfish Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text           : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "6" -> {
                SecretKey key = BlockCiphers.generateTwofishKey(256);
                byte[] iv = BlockCiphers.generateIv16();
                byte[] ct = BlockCiphers.encryptTwofish(input, key, iv);
                byte[] pt = BlockCiphers.decryptTwofish(ct, key, iv);

                System.out.println("Twofish Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text          : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "7" -> {
                SecretKey key = BlockCiphers.generateIdeaKey();
                byte[] iv = BlockCiphers.generateIv8();
                byte[] ct = BlockCiphers.encryptIdea(input, key, iv);
                byte[] pt = BlockCiphers.decryptIdea(ct, key, iv);

                System.out.println("IDEA Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text       : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "8" -> {
                SecretKey key = RivestCiphers.generateRc4Key(16);
                byte[] ct = RivestCiphers.encryptRc4(input, key);
                byte[] pt = RivestCiphers.decryptRc4(ct, key);

                System.out.println("RC4 Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text      : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "9" -> {
                SecretKey key = RivestCiphers.generateRc5Key(16);
                byte[] iv = RivestCiphers.generateIv8();
                byte[] ct = RivestCiphers.encryptRc5(input, key, iv);
                byte[] pt = RivestCiphers.decryptRc5(ct, key, iv);

                System.out.println("RC5 Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text      : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "10" -> {
                SecretKey key = RivestCiphers.generateRc6Key(32);
                byte[] iv = RivestCiphers.generateIv16();
                byte[] ct = RivestCiphers.encryptRc6(input, key, iv);
                byte[] pt = RivestCiphers.decryptRc6(ct, key, iv);

                System.out.println("RC6 Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text      : " + new String(pt, StandardCharsets.UTF_8));
            }
            default -> System.out.println("Invalid symmetric option.");
        }
    }

    private static void handleAsymmetricMenu() {
        System.out.println("\n--- ASYMMETRIC CRYPTOGRAPHY ---");
        System.out.println("1. RSA-OAEP Encryption / Decryption (2048-bit)");
        System.out.println("2. RSA-PSS Signature Creation & Verification");
        System.out.println("3. DSA Signature (2048-bit)");
        System.out.println("4. ECDSA Signature (secp256r1)");
        System.out.println("5. Diffie-Hellman Key Agreement (Group 14 2048-bit)");
        System.out.println("6. ECDH Key Agreement (secp256r1)");
        System.out.print("Choice: ");

        String choice = SCANNER.nextLine().trim();

        switch (choice) {
            case "1" -> {
                String message = promptDefault("Enter plaintext for RSA-OAEP", "Confidential RSA Secret");
                KeyPair kp = RsaService.generateRsaKeyPair(2048);
                byte[] ct = RsaService.encryptOaep(message.getBytes(StandardCharsets.UTF_8), kp.getPublic());
                byte[] pt = RsaService.decryptOaep(ct, kp.getPrivate());

                System.out.println("RSA Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Message   : " + new String(pt, StandardCharsets.UTF_8));
            }
            case "2" -> {
                String message = promptDefault("Enter payload to sign", "Document Payload v1.0");
                byte[] data = message.getBytes(StandardCharsets.UTF_8);
                KeyPair kp = RsaService.generateRsaKeyPair(2048);
                byte[] sig = RsaService.signPss(data, kp.getPrivate());
                boolean valid = RsaService.verifyPss(data, sig, kp.getPublic());

                System.out.println("RSA-PSS Signature (Hex): " + HexUtils.bytesToHex(sig));
                System.out.println("Verification Result    : " + (valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"));
            }
            case "3" -> {
                String message = promptDefault("Enter payload for DSA signature", "DSA Document payload");
                byte[] data = message.getBytes(StandardCharsets.UTF_8);
                KeyPair kp = DigitalSignatureService.generateDsaKeyPair();
                byte[] sig = DigitalSignatureService.signDsa(data, kp.getPrivate());
                boolean valid = DigitalSignatureService.verifyDsa(data, sig, kp.getPublic());

                System.out.println("DSA Signature (Hex): " + HexUtils.bytesToHex(sig));
                System.out.println("Verification Result: " + (valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"));
            }
            case "4" -> {
                String message = promptDefault("Enter payload for ECDSA signature", "ECDSA secp256r1 payload");
                byte[] data = message.getBytes(StandardCharsets.UTF_8);
                KeyPair kp = DigitalSignatureService.generateEcdsaKeyPair();
                byte[] sig = DigitalSignatureService.signEcdsa(data, kp.getPrivate());
                boolean valid = DigitalSignatureService.verifyEcdsa(data, sig, kp.getPublic());

                System.out.println("ECDSA Signature (Hex): " + HexUtils.bytesToHex(sig));
                System.out.println("Verification Result  : " + (valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"));
            }
            case "5" -> {
                System.out.println("Generating DH Group 14 key pairs for Alice and Bob...");
                KeyPair aliceKp = KeyAgreementService.generateDhKeyPairGroup14();
                KeyPair bobKp = KeyAgreementService.generateDhKeyPairGroup14();

                byte[] aliceSecret = KeyAgreementService.deriveDhSharedSecret(aliceKp.getPrivate(), bobKp.getPublic());
                byte[] bobSecret = KeyAgreementService.deriveDhSharedSecret(bobKp.getPrivate(), aliceKp.getPublic());

                System.out.println("Alice Derived Secret (Hex): " + HexUtils.bytesToHex(aliceSecret));
                System.out.println("Bob Derived Secret (Hex)  : " + HexUtils.bytesToHex(bobSecret));
                System.out.println("Shared Secrets Match      : " + HexUtils.bytesToHex(aliceSecret).equals(HexUtils.bytesToHex(bobSecret)));
            }
            case "6" -> {
                System.out.println("Generating ECDH secp256r1 key pairs for Alice and Bob...");
                KeyPair aliceKp = KeyAgreementService.generateEcdhKeyPair();
                KeyPair bobKp = KeyAgreementService.generateEcdhKeyPair();

                byte[] aliceSecret = KeyAgreementService.deriveEcdhSharedSecret(aliceKp.getPrivate(), bobKp.getPublic());
                byte[] bobSecret = KeyAgreementService.deriveEcdhSharedSecret(bobKp.getPrivate(), aliceKp.getPublic());

                System.out.println("Alice ECDH Secret (Hex): " + HexUtils.bytesToHex(aliceSecret));
                System.out.println("Bob ECDH Secret (Hex)  : " + HexUtils.bytesToHex(bobSecret));
                System.out.println("Shared Secrets Match   : " + HexUtils.bytesToHex(aliceSecret).equals(HexUtils.bytesToHex(bobSecret)));
            }
            default -> System.out.println("Invalid asymmetric option.");
        }
    }

    private static void handleHashHmacMenu() {
        System.out.println("\n--- HASH FUNCTIONS & HMAC ---");
        String text = promptDefault("Enter text to hash", "Hash Input Payload");
        byte[] input = text.getBytes(StandardCharsets.UTF_8);

        System.out.println("MD5        : " + HexUtils.bytesToHex(HashHmacService.hashMd5(input)));
        System.out.println("SHA-1      : " + HexUtils.bytesToHex(HashHmacService.hashSha1(input)));
        System.out.println("SHA-224    : " + HexUtils.bytesToHex(HashHmacService.hashSha224(input)));
        System.out.println("SHA-256    : " + HexUtils.bytesToHex(HashHmacService.hashSha256(input)));
        System.out.println("SHA-512    : " + HexUtils.bytesToHex(HashHmacService.hashSha512(input)));
        System.out.println("SHA3-256   : " + HexUtils.bytesToHex(HashHmacService.hashSha3_256(input)));
        System.out.println("SHA3-512   : " + HexUtils.bytesToHex(HashHmacService.hashSha3_512(input)));

        SecretKey hmacKey = HashHmacService.generateHmacKey("HmacSHA256", 256);
        byte[] mac256 = HashHmacService.hmacSha256(input, hmacKey);
        System.out.println("HmacSHA256 : " + HexUtils.bytesToHex(mac256));
    }

    private static void handleHybridPqcMenu() {
        System.out.println("\n--- POST-QUANTUM HYBRID ENVELOPE (FIPS 203 ML-KEM-768) ---");
        String payload = promptDefault("Enter payload for PQC Encryption", "CONFIDENTIAL POST-QUANTUM DATA");
        String aadText = promptDefault("Enter Additional Authenticated Data (AAD)", "RECIPIENT-ID-88492");

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        byte[] aadBytes = aadText.getBytes(StandardCharsets.UTF_8);

        System.out.println("Generating ML-KEM-768 Key Pair...");
        KeyPair kp = HybridPqcService.generateMlKem768KeyPair();

        System.out.println("Encrypting with ML-KEM-768 + HKDF-SHA256 + AES-256-GCM...");
        byte[] wireFormat = HybridPqcService.encryptHybridEnvelope(payloadBytes, kp.getPublic(), aadBytes);

        System.out.println("\nWire Format Encrypted Payload (Base64):");
        System.out.println(HexUtils.bytesToBase64(wireFormat));
        System.out.println("Wire Format Total Length: " + wireFormat.length + " bytes");

        System.out.println("\nDecapsulating and Decrypting with Recipient's ML-KEM-768 Private Key...");
        byte[] decrypted = HybridPqcService.decryptHybridEnvelope(wireFormat, kp.getPrivate());

        System.out.println("Decrypted Payload: " + new String(decrypted, StandardCharsets.UTF_8));
    }

    private static void handleClassicalMenu() {
        System.out.println("\n--- CLASSICAL HISTORICAL CIPHERS ---");
        System.out.println("1. Caesar Cipher");
        System.out.println("2. ROT13");
        System.out.println("3. Vigenère Cipher");
        System.out.print("Choice: ");

        String choice = SCANNER.nextLine().trim();
        String text = promptDefault("Enter text", "Attack At Dawn");

        switch (choice) {
            case "1" -> {
                System.out.print("Enter shift (default 3): ");
                String shiftStr = SCANNER.nextLine().trim();
                int shift = shiftStr.isEmpty() ? 3 : Integer.parseInt(shiftStr);
                String enc = ClassicalCiphers.encryptCaesar(text, shift);
                String dec = ClassicalCiphers.decryptCaesar(enc, shift);
                System.out.println("Caesar Ciphertext : " + enc);
                System.out.println("Decrypted Text    : " + dec);
            }
            case "2" -> {
                String enc = ClassicalCiphers.rot13(text);
                String dec = ClassicalCiphers.rot13(enc);
                System.out.println("ROT13 Ciphertext : " + enc);
                System.out.println("Decrypted Text   : " + dec);
            }
            case "3" -> {
                String key = promptDefault("Enter keyword", "LEMON");
                String enc = ClassicalCiphers.encryptVigenere(text, key);
                String dec = ClassicalCiphers.decryptVigenere(enc, key);
                System.out.println("Vigenère Ciphertext: " + enc);
                System.out.println("Decrypted Text     : " + dec);
            }
            default -> System.out.println("Invalid classical cipher option.");
        }
    }

    private static String promptDefault(String prompt, String defaultValue) {
        System.out.print(prompt + " [Press Enter for '" + defaultValue + "']: ");
        String input = SCANNER.nextLine().trim();
        return input.isEmpty() ? defaultValue : input;
    }
}
