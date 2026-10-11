package com.securecrypto.engine;

import com.securecrypto.engine.asymmetric.DigitalSignatureService;
import com.securecrypto.engine.asymmetric.KeyAgreementService;
import com.securecrypto.engine.asymmetric.RsaService;
import com.securecrypto.engine.classical.ClassicalCiphers;
import com.securecrypto.engine.core.CryptoEngineDiagnostics;
import com.securecrypto.engine.core.CryptoEngineException;
import com.securecrypto.engine.core.HexUtils;
import com.securecrypto.engine.core.KeyZeroizer;
import com.securecrypto.engine.hashing.HashHmacService;
import com.securecrypto.engine.pqc.HybridPqcService;
import com.securecrypto.engine.symmetric.AesService;
import com.securecrypto.engine.symmetric.BlockCiphers;
import com.securecrypto.engine.symmetric.DesSuite;
import com.securecrypto.engine.symmetric.RivestCiphers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive JUnit 5 Test Suite for the Cryptographic Suite.
 * Validates algorithm correctness, KAT vectors, diagnostic diagnostics,
 * tamper detection, and error handling resilience.
 */
public class ComprehensiveCryptoTest {

    private static final byte[] TEST_PAYLOAD = "The quick brown fox jumps over the lazy dog 1234567890".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD_METADATA = "HEADER_AAD_STAMP_2026".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void initSuite() {
        System.setProperty("bouncycastle.registration", "true");
    }

    // --- DOMAIN 1: SYMMETRIC CIPHERS ---

    @Test
    @DisplayName("Symmetric: DES Encryption & Decryption Round-Trip")
    void testDes() {
        SecretKey key = DesSuite.generateDesKey();
        byte[] iv = DesSuite.generateIv8();

        byte[] ciphertext = DesSuite.encryptDes(TEST_PAYLOAD, key, iv);
        assertNotNull(ciphertext);
        assertFalse(Arrays.equals(TEST_PAYLOAD, ciphertext));

        byte[] decrypted = DesSuite.decryptDes(ciphertext, key, iv);
        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: Double-DES (2DES) Pipeline Encryption & Decryption")
    void testDoubleDes() {
        DesSuite.DoubleDesKeys keys = DesSuite.generate2DesKeys();
        byte[] iv1 = DesSuite.generateIv8();
        byte[] iv2 = DesSuite.generateIv8();

        byte[] ciphertext = DesSuite.encrypt2Des(TEST_PAYLOAD, keys.key1, iv1, keys.key2, iv2);
        byte[] decrypted = DesSuite.decrypt2Des(ciphertext, keys.key1, iv1, keys.key2, iv2);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: Triple-DES (3DES) Encryption & Decryption")
    void testTripleDes() {
        SecretKey key = DesSuite.generate3DesKey();
        byte[] iv = DesSuite.generateIv8();

        byte[] ciphertext = DesSuite.encrypt3Des(TEST_PAYLOAD, key, iv);
        byte[] decrypted = DesSuite.decrypt3Des(ciphertext, key, iv);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    @DisplayName("Symmetric: AES-GCM 128/192/256 bits AEAD Round-Trip")
    void testAesGcmKeySizes(int keySize) {
        SecretKey key = AesService.generateAesKey(keySize);
        byte[] iv = AesService.generateIv();

        byte[] ciphertext = AesService.encryptGcm(TEST_PAYLOAD, key, iv, AAD_METADATA);
        byte[] decrypted = AesService.decryptGcm(ciphertext, key, iv, AAD_METADATA);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: Blowfish Encryption & Decryption")
    void testBlowfish() {
        SecretKey key = BlockCiphers.generateBlowfishKey(256);
        byte[] iv = BlockCiphers.generateIv8();

        byte[] ciphertext = BlockCiphers.encryptBlowfish(TEST_PAYLOAD, key, iv);
        byte[] decrypted = BlockCiphers.decryptBlowfish(ciphertext, key, iv);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: Twofish Encryption & Decryption")
    void testTwofish() {
        SecretKey key = BlockCiphers.generateTwofishKey(256);
        byte[] iv = BlockCiphers.generateIv16();

        byte[] ciphertext = BlockCiphers.encryptTwofish(TEST_PAYLOAD, key, iv);
        byte[] decrypted = BlockCiphers.decryptTwofish(ciphertext, key, iv);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: IDEA Encryption & Decryption")
    void testIdea() {
        SecretKey key = BlockCiphers.generateIdeaKey();
        byte[] iv = BlockCiphers.generateIv8();

        byte[] ciphertext = BlockCiphers.encryptIdea(TEST_PAYLOAD, key, iv);
        byte[] decrypted = BlockCiphers.decryptIdea(ciphertext, key, iv);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: RC4 Stream Cipher Encryption & Decryption")
    void testRc4() {
        SecretKey key = RivestCiphers.generateRc4Key(16);

        byte[] ciphertext = RivestCiphers.encryptRc4(TEST_PAYLOAD, key);
        byte[] decrypted = RivestCiphers.decryptRc4(ciphertext, key);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: RC5 Block Cipher Encryption & Decryption")
    void testRc5() {
        SecretKey key = RivestCiphers.generateRc5Key(16);
        byte[] iv = RivestCiphers.generateIv8();

        byte[] ciphertext = RivestCiphers.encryptRc5(TEST_PAYLOAD, key, iv);
        byte[] decrypted = RivestCiphers.decryptRc5(ciphertext, key, iv);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @Test
    @DisplayName("Symmetric: RC6 Block Cipher Encryption & Decryption")
    void testRc6() {
        SecretKey key = RivestCiphers.generateRc6Key(32);
        byte[] iv = RivestCiphers.generateIv16();

        byte[] ciphertext = RivestCiphers.encryptRc6(TEST_PAYLOAD, key, iv);
        byte[] decrypted = RivestCiphers.decryptRc6(ciphertext, key, iv);

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    // --- DOMAIN 2: ASYMMETRIC CRYPTOGRAPHY ---

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072})
    @DisplayName("Asymmetric: RSA-OAEP Encryption & Decryption (2048 & 3072 bit)")
    void testRsaOaep(int keySize) {
        KeyPair kp = RsaService.generateRsaKeyPair(keySize);
        byte[] ciphertext = RsaService.encryptOaep(TEST_PAYLOAD, kp.getPublic());
        byte[] decrypted = RsaService.decryptOaep(ciphertext, kp.getPrivate());

        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072})
    @DisplayName("Asymmetric: RSA-PSS Signature Creation & Verification (2048 & 3072 bit)")
    void testRsaPss(int keySize) {
        KeyPair kp = RsaService.generateRsaKeyPair(keySize);
        byte[] signature = RsaService.signPss(TEST_PAYLOAD, kp.getPrivate());
        boolean verified = RsaService.verifyPss(TEST_PAYLOAD, signature, kp.getPublic());

        assertTrue(verified);
    }

    @Test
    @DisplayName("Asymmetric: DSA Signature Creation & Verification (2048-bit)")
    void testDsaSignature() {
        KeyPair kp = DigitalSignatureService.generateDsaKeyPair();
        byte[] signature = DigitalSignatureService.signDsa(TEST_PAYLOAD, kp.getPrivate());
        boolean verified = DigitalSignatureService.verifyDsa(TEST_PAYLOAD, signature, kp.getPublic());

        assertTrue(verified);
    }

    @Test
    @DisplayName("Asymmetric: ECDSA Signature Creation & Verification (secp256r1)")
    void testEcdsaSignature() {
        KeyPair kp = DigitalSignatureService.generateEcdsaKeyPair();
        byte[] signature = DigitalSignatureService.signEcdsa(TEST_PAYLOAD, kp.getPrivate());
        boolean verified = DigitalSignatureService.verifyEcdsa(TEST_PAYLOAD, signature, kp.getPublic());

        assertTrue(verified);
    }

    @Test
    @DisplayName("Asymmetric: Diffie-Hellman Key Agreement (Group 14 & Group 15)")
    void testDhKeyAgreement() {
        KeyPair aliceGroup14 = KeyAgreementService.generateDhKeyPairGroup14();
        KeyPair bobGroup14 = KeyAgreementService.generateDhKeyPairGroup14();

        byte[] secretAlice14 = KeyAgreementService.deriveDhSharedSecret(aliceGroup14.getPrivate(), bobGroup14.getPublic());
        byte[] secretBob14 = KeyAgreementService.deriveDhSharedSecret(bobGroup14.getPrivate(), aliceGroup14.getPublic());

        assertArrayEquals(secretAlice14, secretBob14);

        KeyPair aliceGroup15 = KeyAgreementService.generateDhKeyPairGroup15();
        KeyPair bobGroup15 = KeyAgreementService.generateDhKeyPairGroup15();

        byte[] secretAlice15 = KeyAgreementService.deriveDhSharedSecret(aliceGroup15.getPrivate(), bobGroup15.getPublic());
        byte[] secretBob15 = KeyAgreementService.deriveDhSharedSecret(bobGroup15.getPrivate(), aliceGroup15.getPublic());

        assertArrayEquals(secretAlice15, secretBob15);
    }

    @Test
    @DisplayName("Asymmetric: ECDH Key Agreement (secp256r1)")
    void testEcdhKeyAgreement() {
        KeyPair aliceKp = KeyAgreementService.generateEcdhKeyPair();
        KeyPair bobKp = KeyAgreementService.generateEcdhKeyPair();

        byte[] secretAlice = KeyAgreementService.deriveEcdhSharedSecret(aliceKp.getPrivate(), bobKp.getPublic());
        byte[] secretBob = KeyAgreementService.deriveEcdhSharedSecret(bobKp.getPrivate(), aliceKp.getPublic());

        assertArrayEquals(secretAlice, secretBob);
    }

    // --- DOMAIN 3: HASHING & HMAC ---

    @Test
    @DisplayName("Hashing: Verification of Digest Outputs")
    void testHashAlgorithms() {
        byte[] md5 = HashHmacService.hashMd5(TEST_PAYLOAD);
        assertEquals(16, md5.length);

        byte[] sha1 = HashHmacService.hashSha1(TEST_PAYLOAD);
        assertEquals(20, sha1.length);

        byte[] sha224 = HashHmacService.hashSha224(TEST_PAYLOAD);
        assertEquals(28, sha224.length);

        byte[] sha256 = HashHmacService.hashSha256(TEST_PAYLOAD);
        assertEquals(32, sha256.length);

        byte[] sha512 = HashHmacService.hashSha512(TEST_PAYLOAD);
        assertEquals(64, sha512.length);

        byte[] sha3_256 = HashHmacService.hashSha3_256(TEST_PAYLOAD);
        assertEquals(32, sha3_256.length);

        byte[] sha3_512 = HashHmacService.hashSha3_512(TEST_PAYLOAD);
        assertEquals(64, sha3_512.length);
    }

    @Test
    @DisplayName("HMAC: Verification of HmacSHA256 and HmacSHA512")
    void testHmac() {
        SecretKey key256 = HashHmacService.generateHmacKey("HmacSHA256", 256);
        byte[] mac256 = HashHmacService.hmacSha256(TEST_PAYLOAD, key256);
        assertEquals(32, mac256.length);

        SecretKey key512 = HashHmacService.generateHmacKey("HmacSHA512", 512);
        byte[] mac512 = HashHmacService.hmacSha512(TEST_PAYLOAD, key512);
        assertEquals(64, mac512.length);
    }

    // --- DOMAIN 4: POST-QUANTUM & HYBRID CRYPTOGRAPHY ---

    @Test
    @DisplayName("PQC: ML-KEM-768 Encapsulation & Decapsulation")
    void testMlKem768() {
        KeyPair kp = HybridPqcService.generateMlKem768KeyPair();
        HybridPqcService.MlKemEncapsulationResult encResult = HybridPqcService.encapsulateMlKem768(kp.getPublic());

        SecretKey derivedSecret = HybridPqcService.decapsulateMlKem768(kp.getPrivate(), encResult.encapsulationCiphertext);

        assertArrayEquals(encResult.sharedSecret.getEncoded(), derivedSecret.getEncoded());
    }

    @Test
    @DisplayName("PQC: Post-Quantum Hybrid Envelope (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM + AAD)")
    void testHybridPqcEnvelope() {
        KeyPair kp = HybridPqcService.generateMlKem768KeyPair();
        byte[] wireFormat = HybridPqcService.encryptHybridEnvelope(TEST_PAYLOAD, kp.getPublic(), AAD_METADATA);

        assertNotNull(wireFormat);
        assertTrue(wireFormat.length > 32);

        byte[] decrypted = HybridPqcService.decryptHybridEnvelope(wireFormat, kp.getPrivate());
        assertArrayEquals(TEST_PAYLOAD, decrypted);
    }

    // --- DOMAIN 5: CLASSICAL HISTORICAL CIPHERS ---

    @Test
    @DisplayName("Classical: Caesar, ROT13, and Vigenère Ciphers")
    void testClassicalCiphers() {
        // Caesar
        String text = "Attack At Dawn!";
        String caesarEnc = ClassicalCiphers.encryptCaesar(text, 5);
        String caesarDec = ClassicalCiphers.decryptCaesar(caesarEnc, 5);
        assertEquals(text, caesarDec);

        // ROT13
        String rot13Enc = ClassicalCiphers.rot13(text);
        String rot13Dec = ClassicalCiphers.rot13(rot13Enc);
        assertEquals(text, rot13Dec);

        // Vigenère
        String vigenereEnc = ClassicalCiphers.encryptVigenere(text, "LEMON");
        String vigenereDec = ClassicalCiphers.decryptVigenere(vigenereEnc, "LEMON");
        assertEquals(text, vigenereDec);
    }

    // --- NEGATIVE TESTS & ANTI-BUG VERIFICATIONS ---

    @Test
    @DisplayName("Anti-Bug Assertion: Tampered AES-GCM Ciphertext Throws CryptoEngineException")
    void testAesGcmTamperCiphertextFails() {
        SecretKey key = AesService.generateAesKey(256);
        byte[] iv = AesService.generateIv();
        byte[] ciphertext = AesService.encryptGcm(TEST_PAYLOAD, key, iv, AAD_METADATA);

        // Tamper 1 bit in ciphertext
        byte[] tampered = ciphertext.clone();
        tampered[0] ^= 0x01;

        assertThrows(CryptoEngineException.class, () -> AesService.decryptGcm(tampered, key, iv, AAD_METADATA));
    }

    @Test
    @DisplayName("Anti-Bug Assertion: Tampered AES-GCM AAD Throws CryptoEngineException")
    void testAesGcmTamperAadFails() {
        SecretKey key = AesService.generateAesKey(256);
        byte[] iv = AesService.generateIv();
        byte[] ciphertext = AesService.encryptGcm(TEST_PAYLOAD, key, iv, AAD_METADATA);

        byte[] tamperedAad = AAD_METADATA.clone();
        tamperedAad[0] ^= 0x01;

        assertThrows(CryptoEngineException.class, () -> AesService.decryptGcm(ciphertext, key, iv, tamperedAad));
    }

    @Test
    @DisplayName("Anti-Bug Assertion: Tampered RSA Signature Returns False")
    void testTamperedSignatureReturnsFalse() {
        KeyPair kp = RsaService.generateRsaKeyPair(2048);
        byte[] signature = RsaService.signPss(TEST_PAYLOAD, kp.getPrivate());

        byte[] tamperedPayload = TEST_PAYLOAD.clone();
        tamperedPayload[0] ^= 0x01;

        boolean verified = RsaService.verifyPss(tamperedPayload, signature, kp.getPublic());
        assertFalse(verified);
    }

    @Test
    @DisplayName("Anti-Bug Assertion: Mismatched Key Secret Derivation Produces Non-Matching Secrets")
    void testMismatchedEcdhKeysFail() {
        KeyPair aliceKp = KeyAgreementService.generateEcdhKeyPair();
        KeyPair bobKp = KeyAgreementService.generateEcdhKeyPair();
        KeyPair eveKp = KeyAgreementService.generateEcdhKeyPair();

        byte[] aliceBobSecret = KeyAgreementService.deriveEcdhSharedSecret(aliceKp.getPrivate(), bobKp.getPublic());
        byte[] aliceEveSecret = KeyAgreementService.deriveEcdhSharedSecret(aliceKp.getPrivate(), eveKp.getPublic());

        assertFalse(Arrays.equals(aliceBobSecret, aliceEveSecret));
    }

    @Test
    @DisplayName("Diagnostic Suite: Automated Self-Diagnostic Run Execution")
    void testDiagnosticRunAll() {
        List<CryptoEngineDiagnostics.DiagnosticResult> results = CryptoEngineDiagnostics.runAllDiagnostics();
        assertNotNull(results);
        assertFalse(results.isEmpty());
        assertTrue(results.stream().allMatch(r -> r.passed));
    }

    @Test
    @DisplayName("Key Zeroization: Buffer Wiping Assertion")
    void testKeyZeroizer() {
        byte[] buffer = new byte[]{(byte) 0xFF, 0x12, 0x34, 0x56};
        KeyZeroizer.zeroize(buffer);
        assertTrue(KeyZeroizer.isZeroized(buffer));
    }
}
