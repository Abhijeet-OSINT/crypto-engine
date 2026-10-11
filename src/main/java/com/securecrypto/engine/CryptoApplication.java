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
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

/**
 * Interactive Terminal CLI Application for the Cryptographic Suite.
 * Features guided submenus for [1. Encrypt, 2. Decrypt, 3. Full Demo]
 * across all symmetric, asymmetric, post-quantum, and classical algorithms.
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
        System.out.println("2. Symmetric Ciphers (Encrypt, Decrypt, Demo for AES, DES, 3DES, Blowfish, Twofish, IDEA, RC4/5/6)");
        System.out.println("3. Asymmetric Cryptography (Encrypt, Decrypt, Sign, Verify for RSA, DSA, ECDSA, DH, ECDH)");
        System.out.println("4. Cryptographic Hashing & HMAC (MD5, SHA-1, SHA-2, SHA-3, HMAC)");
        System.out.println("5. Post-Quantum Cryptography (Encrypt, Decrypt, Demo for ML-KEM-768 Hybrid Envelope)");
        System.out.println("6. Classical Historical Ciphers (Encrypt, Decrypt, Demo for Caesar, ROT13, Vigenère)");
        System.out.println("0. Exit");
        System.out.print("Select choice: ");
    }

    private static String promptMode() {
        System.out.println("\nSelect Operation Mode:");
        System.out.println("  1. Encrypt");
        System.out.println("  2. Decrypt");
        System.out.println("  3. Automated Full Demo (Round-Trip)");
        System.out.print("Action [default 3]: ");
        String mode = SCANNER.nextLine().trim();
        return mode.isEmpty() ? "3" : mode;
    }

    // =========================================================================
    // DOMAIN 1: SYMMETRIC CIPHERS
    // =========================================================================

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

        String cipherChoice = SCANNER.nextLine().trim();

        switch (cipherChoice) {
            case "1" -> handleAesGcm();
            case "2" -> handleDes();
            case "3" -> handle2Des();
            case "4" -> handle3Des();
            case "5" -> handleBlowfish();
            case "6" -> handleTwofish();
            case "7" -> handleIdea();
            case "8" -> handleRc4();
            case "9" -> handleRc5();
            case "10" -> handleRc6();
            default -> System.out.println("[!] Invalid symmetric cipher option.");
        }
    }

    private static void handleAesGcm() {
        System.out.println("\n[ AES-256-GCM AEAD ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext message to encrypt", "Confidential AES Payload");
                String aadStr = promptDefault("Enter Additional Authenticated Data (AAD)", "METADATA-HEADER");
                SecretKey key = AesService.generateAesKey(256);
                byte[] iv = AesService.generateIv();
                byte[] ct = AesService.encryptGcm(pt.getBytes(StandardCharsets.UTF_8), key, iv, aadStr.getBytes(StandardCharsets.UTF_8));

                System.out.println("\n--- ENCRYPTION RESULT ---");
                System.out.println("Key (Hex)        : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 12B)    : " + HexUtils.bytesToHex(iv));
                System.out.println("AAD (Text)       : " + aadStr);
                System.out.println("Ciphertext (Hex) : " + HexUtils.bytesToHex(ct));
                System.out.println("Ciphertext (B64) : " + HexUtils.bytesToBase64(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex or Base64)");
                String keyHex = promptRequired("Enter 256-bit Key (64-char Hex)");
                String ivHex = promptRequired("Enter 96-bit IV (24-char Hex)");
                String aadStr = promptDefault("Enter AAD string (leave empty if none)", "");

                byte[] ctBytes = parseBytes(ctHex);
                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "AES");
                byte[] iv = HexUtils.hexToBytes(ivHex);
                byte[] aadBytes = aadStr.isEmpty() ? null : aadStr.getBytes(StandardCharsets.UTF_8);

                byte[] decrypted = AesService.decryptGcm(ctBytes, key, iv, aadBytes);
                System.out.println("\n--- DECRYPTION RESULT ---");
                System.out.println("Decrypted Plaintext: " + new String(decrypted, StandardCharsets.UTF_8));
            }
            default -> {
                String pt = promptDefault("Enter plaintext message", "AES Round-Trip Demonstration");
                SecretKey key = AesService.generateAesKey(256);
                byte[] iv = AesService.generateIv();
                byte[] aad = "HEADER-METADATA".getBytes(StandardCharsets.UTF_8);

                byte[] ct = AesService.encryptGcm(pt.getBytes(StandardCharsets.UTF_8), key, iv, aad);
                byte[] decrypted = AesService.decryptGcm(ct, key, iv, aad);

                System.out.println("Generated Key (Hex): " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("Generated IV (Hex) : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex)   : " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Plaintext: " + new String(decrypted, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleDes() {
        System.out.println("\n[ DES (Single 56-bit CBC) ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext to encrypt", "DES Secret Message");
                SecretKey key = DesSuite.generateDesKey();
                byte[] iv = DesSuite.generateIv8();
                byte[] ct = DesSuite.encryptDes(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 8B)   : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 8B)    : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter 56-bit DES Key (16-char Hex)");
                String ivHex = promptRequired("Enter 8-byte IV (16-char Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "DES");
                byte[] decrypted = DesSuite.decryptDes(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(decrypted, StandardCharsets.UTF_8));
            }
            default -> {
                String pt = promptDefault("Enter plaintext", "DES Demonstration Payload");
                SecretKey key = DesSuite.generateDesKey();
                byte[] iv = DesSuite.generateIv8();
                byte[] ct = DesSuite.encryptDes(pt.getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = DesSuite.decryptDes(ct, key, iv);

                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handle2Des() {
        System.out.println("\n[ Double-DES (2DES Pipeline) ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "2DES Payload");
                DesSuite.DoubleDesKeys keys = DesSuite.generate2DesKeys();
                byte[] iv1 = DesSuite.generateIv8();
                byte[] iv2 = DesSuite.generateIv8();
                byte[] ct = DesSuite.encrypt2Des(pt.getBytes(StandardCharsets.UTF_8), keys.key1, iv1, keys.key2, iv2);

                System.out.println("Key 1 (Hex): " + HexUtils.bytesToHex(keys.key1.getEncoded()));
                System.out.println("IV 1 (Hex) : " + HexUtils.bytesToHex(iv1));
                System.out.println("Key 2 (Hex): " + HexUtils.bytesToHex(keys.key2.getEncoded()));
                System.out.println("IV 2 (Hex) : " + HexUtils.bytesToHex(iv2));
                System.out.println("2DES Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String k1Hex = promptRequired("Enter Key 1 (Hex)");
                String iv1Hex = promptRequired("Enter IV 1 (Hex)");
                String k2Hex = promptRequired("Enter Key 2 (Hex)");
                String iv2Hex = promptRequired("Enter IV 2 (Hex)");

                SecretKey k1 = new SecretKeySpec(HexUtils.hexToBytes(k1Hex), "DES");
                SecretKey k2 = new SecretKeySpec(HexUtils.hexToBytes(k2Hex), "DES");
                byte[] dec = DesSuite.decrypt2Des(HexUtils.hexToBytes(ctHex), k1, HexUtils.hexToBytes(iv1Hex), k2, HexUtils.hexToBytes(iv2Hex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                DesSuite.DoubleDesKeys keys = DesSuite.generate2DesKeys();
                byte[] iv1 = DesSuite.generateIv8();
                byte[] iv2 = DesSuite.generateIv8();
                byte[] ct = DesSuite.encrypt2Des("2DES Demo Text".getBytes(StandardCharsets.UTF_8), keys.key1, iv1, keys.key2, iv2);
                byte[] dec = DesSuite.decrypt2Des(ct, keys.key1, iv1, keys.key2, iv2);
                System.out.println("2DES Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text       : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handle3Des() {
        System.out.println("\n[ Triple-DES (3DES / DESede) ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "3DES Secret Payload");
                SecretKey key = DesSuite.generate3DesKey();
                byte[] iv = DesSuite.generateIv8();
                byte[] ct = DesSuite.encrypt3Des(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 24B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 8B)    : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter 168-bit 3DES Key (48-char Hex)");
                String ivHex = promptRequired("Enter 8-byte IV (16-char Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "DESede");
                byte[] dec = DesSuite.decrypt3Des(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = DesSuite.generate3DesKey();
                byte[] iv = DesSuite.generateIv8();
                byte[] ct = DesSuite.encrypt3Des("3DES Demonstration".getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = DesSuite.decrypt3Des(ct, key, iv);
                System.out.println("3DES Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text       : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleBlowfish() {
        System.out.println("\n[ Blowfish (CBC/PKCS7Padding) ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "Blowfish Payload");
                SecretKey key = BlockCiphers.generateBlowfishKey(256);
                byte[] iv = BlockCiphers.generateIv8();
                byte[] ct = BlockCiphers.encryptBlowfish(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 32B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 8B)    : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter Blowfish Key (Hex)");
                String ivHex = promptRequired("Enter 8-byte IV (Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "Blowfish");
                byte[] dec = BlockCiphers.decryptBlowfish(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = BlockCiphers.generateBlowfishKey(256);
                byte[] iv = BlockCiphers.generateIv8();
                byte[] ct = BlockCiphers.encryptBlowfish("Blowfish Demo".getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = BlockCiphers.decryptBlowfish(ct, key, iv);
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleTwofish() {
        System.out.println("\n[ Twofish (CBC/PKCS7Padding) ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "Twofish Payload");
                SecretKey key = BlockCiphers.generateTwofishKey(256);
                byte[] iv = BlockCiphers.generateIv16();
                byte[] ct = BlockCiphers.encryptTwofish(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 32B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 16B)   : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter Twofish Key (Hex)");
                String ivHex = promptRequired("Enter 16-byte IV (Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "Twofish");
                byte[] dec = BlockCiphers.decryptTwofish(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = BlockCiphers.generateTwofishKey(256);
                byte[] iv = BlockCiphers.generateIv16();
                byte[] ct = BlockCiphers.encryptTwofish("Twofish Demo".getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = BlockCiphers.decryptTwofish(ct, key, iv);
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleIdea() {
        System.out.println("\n[ IDEA (128-bit CBC) ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "IDEA Payload");
                SecretKey key = BlockCiphers.generateIdeaKey();
                byte[] iv = BlockCiphers.generateIv8();
                byte[] ct = BlockCiphers.encryptIdea(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 16B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 8B)    : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter 128-bit IDEA Key (32-char Hex)");
                String ivHex = promptRequired("Enter 8-byte IV (16-char Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "IDEA");
                byte[] dec = BlockCiphers.decryptIdea(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = BlockCiphers.generateIdeaKey();
                byte[] iv = BlockCiphers.generateIv8();
                byte[] ct = BlockCiphers.encryptIdea("IDEA Demonstration".getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = BlockCiphers.decryptIdea(ct, key, iv);
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleRc4() {
        System.out.println("\n[ RC4 Stream Cipher ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "RC4 Stream Text");
                SecretKey key = RivestCiphers.generateRc4Key(16);
                byte[] ct = RivestCiphers.encryptRc4(pt.getBytes(StandardCharsets.UTF_8), key);

                System.out.println("Key (Hex, 16B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter RC4 Key (Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "RC4");
                byte[] dec = RivestCiphers.decryptRc4(HexUtils.hexToBytes(ctHex), key);
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = RivestCiphers.generateRc4Key(16);
                byte[] ct = RivestCiphers.encryptRc4("RC4 Stream Demo".getBytes(StandardCharsets.UTF_8), key);
                byte[] dec = RivestCiphers.decryptRc4(ct, key);
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleRc5() {
        System.out.println("\n[ RC5 Block Cipher ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "RC5 Payload");
                SecretKey key = RivestCiphers.generateRc5Key(16);
                byte[] iv = RivestCiphers.generateIv8();
                byte[] ct = RivestCiphers.encryptRc5(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 16B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 8B)    : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter RC5 Key (Hex)");
                String ivHex = promptRequired("Enter 8-byte IV (Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "RC5");
                byte[] dec = RivestCiphers.decryptRc5(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = RivestCiphers.generateRc5Key(16);
                byte[] iv = RivestCiphers.generateIv8();
                byte[] ct = RivestCiphers.encryptRc5("RC5 Demonstration".getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = RivestCiphers.decryptRc5(ct, key, iv);
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    private static void handleRc6() {
        System.out.println("\n[ RC6 Block Cipher ]");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String pt = promptDefault("Enter plaintext", "RC6 Payload");
                SecretKey key = RivestCiphers.generateRc6Key(32);
                byte[] iv = RivestCiphers.generateIv16();
                byte[] ct = RivestCiphers.encryptRc6(pt.getBytes(StandardCharsets.UTF_8), key, iv);

                System.out.println("Key (Hex, 32B)  : " + HexUtils.bytesToHex(key.getEncoded()));
                System.out.println("IV (Hex, 16B)   : " + HexUtils.bytesToHex(iv));
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
            }
            case "2" -> {
                String ctHex = promptRequired("Enter Ciphertext (Hex)");
                String keyHex = promptRequired("Enter RC6 Key (Hex)");
                String ivHex = promptRequired("Enter 16-byte IV (Hex)");

                SecretKey key = new SecretKeySpec(HexUtils.hexToBytes(keyHex), "RC6");
                byte[] dec = RivestCiphers.decryptRc6(HexUtils.hexToBytes(ctHex), key, HexUtils.hexToBytes(ivHex));
                System.out.println("Decrypted Plaintext: " + new String(dec, StandardCharsets.UTF_8));
            }
            default -> {
                SecretKey key = RivestCiphers.generateRc6Key(32);
                byte[] iv = RivestCiphers.generateIv16();
                byte[] ct = RivestCiphers.encryptRc6("RC6 Demonstration".getBytes(StandardCharsets.UTF_8), key, iv);
                byte[] dec = RivestCiphers.decryptRc6(ct, key, iv);
                System.out.println("Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                System.out.println("Decrypted Text  : " + new String(dec, StandardCharsets.UTF_8));
            }
        }
    }

    // =========================================================================
    // DOMAIN 2: ASYMMETRIC CRYPTOGRAPHY
    // =========================================================================

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
                System.out.println("\n[ RSA-OAEP (2048-bit) ]");
                String mode = promptMode();
                switch (mode) {
                    case "1" -> {
                        String pt = promptDefault("Enter plaintext for RSA-OAEP", "Confidential RSA Secret");
                        KeyPair kp = RsaService.generateRsaKeyPair(2048);
                        byte[] ct = RsaService.encryptOaep(pt.getBytes(StandardCharsets.UTF_8), kp.getPublic());

                        System.out.println("\nGenerated Public Key (Base64) : " + HexUtils.bytesToBase64(kp.getPublic().getEncoded()));
                        System.out.println("Generated Private Key (Base64): " + HexUtils.bytesToBase64(kp.getPrivate().getEncoded()));
                        System.out.println("RSA Ciphertext (Hex)          : " + HexUtils.bytesToHex(ct));
                    }
                    case "2" -> {
                        String ctHex = promptRequired("Enter RSA Ciphertext (Hex)");
                        String privKeyB64 = promptRequired("Enter RSA Private Key (PKCS#8 Base64)");
                        try {
                            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(HexUtils.base64ToBytes(privKeyB64));
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            PrivateKey privKey = kf.generatePrivate(keySpec);

                            byte[] pt = RsaService.decryptOaep(HexUtils.hexToBytes(ctHex), privKey);
                            System.out.println("Decrypted Plaintext: " + new String(pt, StandardCharsets.UTF_8));
                        } catch (Exception e) {
                            throw new CryptoEngineException("RSA Private Key parsing or decryption failed", e);
                        }
                    }
                    default -> {
                        KeyPair kp = RsaService.generateRsaKeyPair(2048);
                        byte[] ct = RsaService.encryptOaep("RSA Secret Demo".getBytes(StandardCharsets.UTF_8), kp.getPublic());
                        byte[] pt = RsaService.decryptOaep(ct, kp.getPrivate());
                        System.out.println("RSA Ciphertext (Hex): " + HexUtils.bytesToHex(ct));
                        System.out.println("Decrypted Message   : " + new String(pt, StandardCharsets.UTF_8));
                    }
                }
            }
            case "2" -> {
                System.out.println("\n[ RSA-PSS Digital Signatures ]");
                System.out.println("1. Sign Data");
                System.out.println("2. Verify Signature");
                System.out.println("3. Automated Demo");
                System.out.print("Action [default 3]: ");
                String action = SCANNER.nextLine().trim();

                if ("1".equals(action)) {
                    String data = promptDefault("Enter message to sign", "Document Payload v1.0");
                    KeyPair kp = RsaService.generateRsaKeyPair(2048);
                    byte[] sig = RsaService.signPss(data.getBytes(StandardCharsets.UTF_8), kp.getPrivate());

                    System.out.println("Public Key (Base64) : " + HexUtils.bytesToBase64(kp.getPublic().getEncoded()));
                    System.out.println("Signature (Hex)     : " + HexUtils.bytesToHex(sig));
                } else if ("2".equals(action)) {
                    String data = promptRequired("Enter original data/message");
                    String sigHex = promptRequired("Enter Signature (Hex)");
                    String pubKeyB64 = promptRequired("Enter Public Key (X.509 Base64)");
                    try {
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(HexUtils.base64ToBytes(pubKeyB64));
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        PublicKey pubKey = kf.generatePublic(keySpec);

                        boolean valid = RsaService.verifyPss(data.getBytes(StandardCharsets.UTF_8), HexUtils.hexToBytes(sigHex), pubKey);
                        System.out.println("Verification Result : " + (valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"));
                    } catch (Exception e) {
                        throw new CryptoEngineException("Key parsing failed: " + e.getMessage(), e);
                    }
                } else {
                    KeyPair kp = RsaService.generateRsaKeyPair(2048);
                    byte[] data = "Document Demo Payload".getBytes(StandardCharsets.UTF_8);
                    byte[] sig = RsaService.signPss(data, kp.getPrivate());
                    boolean valid = RsaService.verifyPss(data, sig, kp.getPublic());
                    System.out.println("Signature (Hex)     : " + HexUtils.bytesToHex(sig));
                    System.out.println("Verification Result : " + (valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"));
                }
            }
            case "3" -> {
                KeyPair kp = DigitalSignatureService.generateDsaKeyPair();
                byte[] data = "DSA Document".getBytes(StandardCharsets.UTF_8);
                byte[] sig = DigitalSignatureService.signDsa(data, kp.getPrivate());
                boolean valid = DigitalSignatureService.verifyDsa(data, sig, kp.getPublic());
                System.out.println("DSA Signature (Hex) : " + HexUtils.bytesToHex(sig));
                System.out.println("Verification Result : " + (valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"));
            }
            case "4" -> {
                KeyPair kp = DigitalSignatureService.generateEcdsaKeyPair();
                byte[] data = "ECDSA secp256r1 data".getBytes(StandardCharsets.UTF_8);
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

    // =========================================================================
    // DOMAIN 3: HASHING & HMAC
    // =========================================================================

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

    // =========================================================================
    // DOMAIN 4: POST-QUANTUM HYBRID ENVELOPE
    // =========================================================================

    private static void handleHybridPqcMenu() {
        System.out.println("\n--- POST-QUANTUM HYBRID ENVELOPE (FIPS 203 ML-KEM-768) ---");
        String mode = promptMode();
        switch (mode) {
            case "1" -> {
                String payload = promptDefault("Enter payload for PQC Encryption", "CONFIDENTIAL POST-QUANTUM DATA");
                String aadText = promptDefault("Enter Additional Authenticated Data (AAD)", "RECIPIENT-ID-88492");

                System.out.println("Generating ML-KEM-768 Recipient Key Pair...");
                KeyPair kp = HybridPqcService.generateMlKem768KeyPair();
                byte[] wireFormat = HybridPqcService.encryptHybridEnvelope(
                        payload.getBytes(StandardCharsets.UTF_8),
                        kp.getPublic(),
                        aadText.getBytes(StandardCharsets.UTF_8)
                );

                System.out.println("\nRecipient Private Key (Base64):");
                System.out.println(HexUtils.bytesToBase64(kp.getPrivate().getEncoded()));
                System.out.println("\nEncrypted Wire Format Payload (Base64):");
                System.out.println(HexUtils.bytesToBase64(wireFormat));
            }
            case "2" -> {
                String wireB64 = promptRequired("Enter Encrypted Wire Format Payload (Base64)");
                String privKeyB64 = promptRequired("Enter Recipient ML-KEM-768 Private Key (Base64)");
                try {
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(HexUtils.base64ToBytes(privKeyB64));
                    KeyFactory kf = KeyFactory.getInstance("ML-KEM-768", HybridPqcService.BC_PROVIDER);
                    PrivateKey privKey = kf.generatePrivate(keySpec);

                    byte[] decrypted = HybridPqcService.decryptHybridEnvelope(HexUtils.base64ToBytes(wireB64), privKey);
                    System.out.println("\n--- DECRYPTION RESULT ---");
                    System.out.println("Decrypted Payload: " + new String(decrypted, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    throw new CryptoEngineException("PQC Decryption failed: " + e.getMessage(), e);
                }
            }
            default -> {
                KeyPair kp = HybridPqcService.generateMlKem768KeyPair();
                byte[] payload = "CONFIDENTIAL POST-QUANTUM DATA".getBytes(StandardCharsets.UTF_8);
                byte[] aad = "RECIPIENT-ID-88492".getBytes(StandardCharsets.UTF_8);

                byte[] wireFormat = HybridPqcService.encryptHybridEnvelope(payload, kp.getPublic(), aad);
                byte[] decrypted = HybridPqcService.decryptHybridEnvelope(wireFormat, kp.getPrivate());

                System.out.println("Encrypted Wire Format Length : " + wireFormat.length + " bytes");
                System.out.println("Encrypted Wire Format (Base64): " + HexUtils.bytesToBase64(wireFormat));
                System.out.println("Decrypted Payload            : " + new String(decrypted, StandardCharsets.UTF_8));
            }
        }
    }

    // =========================================================================
    // DOMAIN 5: CLASSICAL HISTORICAL CIPHERS
    // =========================================================================

    private static void handleClassicalMenu() {
        System.out.println("\n--- CLASSICAL HISTORICAL CIPHERS ---");
        System.out.println("1. Caesar Cipher");
        System.out.println("2. ROT13");
        System.out.println("3. Vigenère Cipher");
        System.out.print("Choice: ");

        String choice = SCANNER.nextLine().trim();

        switch (choice) {
            case "1" -> {
                System.out.println("\n[ Caesar Cipher ]");
                String mode = promptMode();
                if ("1".equals(mode)) {
                    String text = promptDefault("Enter plaintext", "ATTACK AT DAWN");
                    int shift = promptInt("Enter shift (0-25)", 3);
                    String enc = ClassicalCiphers.encryptCaesar(text, shift);
                    System.out.println("Caesar Ciphertext: " + enc);
                } else if ("2".equals(mode)) {
                    String text = promptDefault("Enter ciphertext", "DWWDFN DW GDZQ");
                    int shift = promptInt("Enter shift (0-25)", 3);
                    String dec = ClassicalCiphers.decryptCaesar(text, shift);
                    System.out.println("Decrypted Plaintext: " + dec);
                } else {
                    String text = "ATTACK AT DAWN";
                    String enc = ClassicalCiphers.encryptCaesar(text, 3);
                    String dec = ClassicalCiphers.decryptCaesar(enc, 3);
                    System.out.println("Original Text    : " + text);
                    System.out.println("Caesar Ciphertext: " + enc);
                    System.out.println("Decrypted Text   : " + dec);
                }
            }
            case "2" -> {
                System.out.println("\n[ ROT13 (Self-Inverse) ]");
                String text = promptDefault("Enter text", "Hello World");
                String rotated = ClassicalCiphers.rot13(text);
                System.out.println("ROT13 Output: " + rotated);
            }
            case "3" -> {
                System.out.println("\n[ Vigenère Cipher ]");
                String mode = promptMode();
                if ("1".equals(mode)) {
                    String text = promptDefault("Enter plaintext", "ATTACK AT DAWN");
                    String key = promptDefault("Enter keyword", "LEMON");
                    String enc = ClassicalCiphers.encryptVigenere(text, key);
                    System.out.println("Vigenère Ciphertext: " + enc);
                } else if ("2".equals(mode)) {
                    String text = promptDefault("Enter ciphertext", "LXFOPV EF RNHR");
                    String key = promptDefault("Enter keyword", "LEMON");
                    String dec = ClassicalCiphers.decryptVigenere(text, key);
                    System.out.println("Decrypted Plaintext: " + dec);
                } else {
                    String text = "ATTACK AT DAWN";
                    String key = "LEMON";
                    String enc = ClassicalCiphers.encryptVigenere(text, key);
                    String dec = ClassicalCiphers.decryptVigenere(enc, key);
                    System.out.println("Original Text      : " + text);
                    System.out.println("Vigenère Ciphertext: " + enc);
                    System.out.println("Decrypted Text     : " + dec);
                }
            }
            default -> System.out.println("Invalid classical cipher option.");
        }
    }

    // =========================================================================
    // CLI HELPER UTILITIES
    // =========================================================================

    private static String promptDefault(String prompt, String defaultValue) {
        System.out.print(prompt + " [Press Enter for '" + defaultValue + "']: ");
        String input = SCANNER.nextLine().trim();
        return input.isEmpty() ? defaultValue : input;
    }

    private static String promptRequired(String prompt) {
        while (true) {
            System.out.print(prompt + ": ");
            String input = SCANNER.nextLine().trim();
            if (!input.isEmpty()) {
                return input;
            }
            System.out.println("[!] Input cannot be empty. Please enter a value.");
        }
    }

    private static int promptInt(String prompt, int defaultValue) {
        System.out.print(prompt + " [Press Enter for " + defaultValue + "]: ");
        String input = SCANNER.nextLine().trim();
        if (input.isEmpty()) return defaultValue;
        try {
            return Integer.parseInt(input);
        } catch (NumberFormatException e) {
            System.out.println("[!] Invalid number. Using default " + defaultValue);
            return defaultValue;
        }
    }

    private static byte[] parseBytes(String input) {
        if (input == null || input.isBlank()) return new byte[0];
        String clean = input.trim();
        try {
            // If it's valid hex (contains only 0-9, a-f, A-F and even length)
            if (clean.matches("^[0-9a-fA-F]+$") && clean.length() % 2 == 0) {
                return HexUtils.hexToBytes(clean);
            }
            // Otherwise parse as Base64
            return HexUtils.base64ToBytes(clean);
        } catch (Exception e) {
            // Fallback attempt hex
            return HexUtils.hexToBytes(clean);
        }
    }
}
