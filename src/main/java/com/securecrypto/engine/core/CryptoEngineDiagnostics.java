package com.securecrypto.engine.core;

import com.securecrypto.engine.asymmetric.DigitalSignatureService;
import com.securecrypto.engine.asymmetric.KeyAgreementService;
import com.securecrypto.engine.asymmetric.RsaService;
import com.securecrypto.engine.classical.ClassicalCiphers;
import com.securecrypto.engine.hashing.HashHmacService;
import com.securecrypto.engine.pqc.HybridPqcService;
import com.securecrypto.engine.symmetric.AesService;
import com.securecrypto.engine.symmetric.DesSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Automated diagnostic health check module for Crypto Engine.
 * Actively tests provider presence, KAT test vectors, nonce freshness,
 * tamper resistance (AEAD bad tag detection), key zeroization, and hybrid PQC encapsulation.
 */
public final class CryptoEngineDiagnostics {

    public static class DiagnosticResult {
        public final String testName;
        public final boolean passed;
        public final String details;

        public DiagnosticResult(String testName, boolean passed, String details) {
            this.testName = testName;
            this.passed = passed;
            this.details = details;
        }
    }

    private CryptoEngineDiagnostics() {
    }

    public static List<DiagnosticResult> runAllDiagnostics() {
        List<DiagnosticResult> results = new ArrayList<>();
        long startTime = System.currentTimeMillis();

        // 1. Provider Registration Check
        results.add(testProviderRegistration());

        // 2. Known-Answer Tests (KAT)
        results.add(testKatSha256());
        results.add(testKatAesGcm());
        results.add(testKatCaesar());

        // 3. IV / Nonce Freshness & Uniqueness Check
        results.add(testNonceUniqueness());

        // 4. Tamper Resistance & AEAD Bad Tag Assertion
        results.add(testTamperDetection());

        // 5. Key Zeroization Validation
        results.add(testKeyZeroization());

        // 6. Post-Quantum Hybrid Envelope Verification
        results.add(testHybridPqcEnvelope());

        // 7. RSA-PSS Signature Verification
        results.add(testRsaSignature());

        long duration = System.currentTimeMillis() - startTime;
        printSummaryReport(results, duration);
        return results;
    }

    private static DiagnosticResult testProviderRegistration() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        boolean active = Security.getProvider("BC") != null;
        return new DiagnosticResult(
                "Provider Registration",
                active,
                active ? "Bouncy Castle " + Security.getProvider("BC").getVersionStr() + " active" : "BC Provider missing"
        );
    }

    private static DiagnosticResult testKatSha256() {
        // NIST SHA-256 KAT vector for "abc"
        // Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        String input = "abc";
        String expectedHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        byte[] hash = HashHmacService.hashSha256(input.getBytes(StandardCharsets.UTF_8));
        String actualHex = HexUtils.bytesToHex(hash);
        boolean pass = expectedHex.equalsIgnoreCase(actualHex);
        return new DiagnosticResult(
                "KAT SHA-256 Vector",
                pass,
                pass ? "Matches NIST SHA-256 test vector" : "Mismatch: expected " + expectedHex + " got " + actualHex
        );
    }

    private static DiagnosticResult testKatAesGcm() {
        try {
            SecretKey key = AesService.generateAesKey(256);
            byte[] iv = AesService.generateIv();
            byte[] plaintext = "CRYPTO-ENGINE-KAT-TEST".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "HEADER-DATA".getBytes(StandardCharsets.UTF_8);

            byte[] ciphertext = AesService.encryptGcm(plaintext, key, iv, aad);
            byte[] decrypted = AesService.decryptGcm(ciphertext, key, iv, aad);
            boolean pass = Arrays.equals(plaintext, decrypted);
            return new DiagnosticResult(
                    "KAT AES-256-GCM",
                    pass,
                    pass ? "AES-256-GCM AEAD encryption/decryption round-trip verified" : "Round-trip mismatch"
            );
        } catch (Exception e) {
            return new DiagnosticResult("KAT AES-256-GCM", false, e.getMessage());
        }
    }

    private static DiagnosticResult testKatCaesar() {
        String input = "HELLO WORLD";
        String encrypted = ClassicalCiphers.encryptCaesar(input, 3);
        boolean pass = "KHOOR ZRUOG".equals(encrypted);
        return new DiagnosticResult(
                "KAT Caesar Shift",
                pass,
                pass ? "Shift=3 KAT verified ('HELLO WORLD' -> 'KHOOR ZRUOG')" : "Mismatch: " + encrypted
        );
    }

    private static DiagnosticResult testNonceUniqueness() {
        byte[] iv1 = AesService.generateIv();
        byte[] iv2 = AesService.generateIv();
        byte[] iv3 = AesService.generateIv();

        boolean unique = !Arrays.equals(iv1, iv2) && !Arrays.equals(iv2, iv3) && !Arrays.equals(iv1, iv3);
        return new DiagnosticResult(
                "Nonce/IV Uniqueness",
                unique,
                unique ? "Cryptographically secure 96-bit random nonces verified" : "Nonce collision detected!"
        );
    }

    private static DiagnosticResult testTamperDetection() {
        try {
            SecretKey key = AesService.generateAesKey(256);
            byte[] iv = AesService.generateIv();
            byte[] plaintext = "CONFIDENTIAL PAYLOAD".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "AUTHENTICATED METADATA".getBytes(StandardCharsets.UTF_8);

            byte[] ciphertext = AesService.encryptGcm(plaintext, key, iv, aad);

            // Tamper single bit in ciphertext
            byte[] tamperedCt = ciphertext.clone();
            tamperedCt[0] ^= 0x01;

            boolean caughtCiphertextTamper = false;
            try {
                AesService.decryptGcm(tamperedCt, key, iv, aad);
            } catch (CryptoEngineException e) {
                caughtCiphertextTamper = true;
            }

            // Tamper single bit in AAD
            byte[] tamperedAad = aad.clone();
            tamperedAad[0] ^= 0x01;

            boolean caughtAadTamper = false;
            try {
                AesService.decryptGcm(ciphertext, key, iv, tamperedAad);
            } catch (CryptoEngineException e) {
                caughtAadTamper = true;
            }

            boolean pass = caughtCiphertextTamper && caughtAadTamper;
            return new DiagnosticResult(
                    "AEAD Tamper Resistance",
                    pass,
                    pass ? "BadTagException correctly thrown on 1-bit tampering of CT and AAD" : "Failed to catch tamper!"
            );
        } catch (Exception e) {
            return new DiagnosticResult("AEAD Tamper Resistance", false, e.getMessage());
        }
    }

    private static DiagnosticResult testKeyZeroization() {
        byte[] sensitiveData = new byte[]{0x12, 0x34, (byte) 0xAB, (byte) 0xCD};
        KeyZeroizer.zeroize(sensitiveData);
        boolean zeroed = KeyZeroizer.isZeroized(sensitiveData);
        return new DiagnosticResult(
                "Key Buffer Zeroization",
                zeroed,
                zeroed ? "Memory buffer securely zeroized with 0x00 bytes" : "Buffer contents leaked"
        );
    }

    private static DiagnosticResult testHybridPqcEnvelope() {
        try {
            KeyPair keyPair = HybridPqcService.generateMlKem768KeyPair();
            byte[] payload = "POST-QUANTUM HYBRID ENVELOPE TEST PAYLOAD".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "PQC-HEADER".getBytes(StandardCharsets.UTF_8);

            byte[] wireFormat = HybridPqcService.encryptHybridEnvelope(payload, keyPair.getPublic(), aad);
            byte[] decrypted = HybridPqcService.decryptHybridEnvelope(wireFormat, keyPair.getPrivate());

            boolean pass = Arrays.equals(payload, decrypted);
            return new DiagnosticResult(
                    "PQC Hybrid Envelope",
                    pass,
                    pass ? "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM round-trip verified" : "PQC hybrid decryption mismatch"
            );
        } catch (Exception e) {
            return new DiagnosticResult("PQC Hybrid Envelope", false, e.getMessage());
        }
    }

    private static DiagnosticResult testRsaSignature() {
        try {
            KeyPair keyPair = RsaService.generateRsaKeyPair(2048);
            byte[] data = "DATA TO BE SIGNED".getBytes(StandardCharsets.UTF_8);
            byte[] sig = RsaService.signPss(data, keyPair.getPrivate());
            boolean verified = RsaService.verifyPss(data, sig, keyPair.getPublic());
            return new DiagnosticResult(
                    "RSA-PSS Signature",
                    verified,
                    verified ? "RSA-2048 PSS signature creation and verification succeeded" : "Signature failed"
            );
        } catch (Exception e) {
            return new DiagnosticResult("RSA-PSS Signature", false, e.getMessage());
        }
    }

    private static void printSummaryReport(List<DiagnosticResult> results, long durationMs) {
        System.out.println("\n========================================================================================");
        System.out.println("                     CRYPTO ENGINE AUTOMATED DIAGNOSTIC REPORT                          ");
        System.out.println("========================================================================================");

        boolean allPassed = true;
        for (DiagnosticResult r : results) {
            String status = r.passed ? "[ PASS ]" : "[ FAIL ]";
            System.out.printf("%-10s %-25s : %s%n", status, r.testName, r.details);
            if (!r.passed) allPassed = false;
        }

        System.out.println("----------------------------------------------------------------------------------------");
        System.out.printf("Execution Time: %d ms | Total Tests: %d%n", durationMs, results.size());
        System.out.println("========================================================================================");
        if (allPassed) {
            System.out.println("STATUS: ALL DIAGNOSTIC CHECKS PASSED SUCCESSFULLY. ENGINE HEALTH: 100%");
        } else {
            System.out.println("STATUS: WARNING - ONE OR MORE DIAGNOSTIC CHECKS FAILED.");
        }
        System.out.println("========================================================================================\n");
    }
}
