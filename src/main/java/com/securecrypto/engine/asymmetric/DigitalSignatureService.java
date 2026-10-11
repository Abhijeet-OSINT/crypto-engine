package com.securecrypto.engine.asymmetric;

import com.securecrypto.engine.core.CryptoEngineException;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Service for DSA (FIPS 186-4 2048-bit) and ECDSA (secp256r1) Digital Signatures.
 */
public final class DigitalSignatureService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private DigitalSignatureService() {
    }

    // --- DSA (FIPS 186-4) ---

    public static KeyPair generateDsaKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            keyGen.initialize(2048, RANDOM);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoEngineException("Failed to generate DSA key pair", e);
        }
    }

    public static byte[] signDsa(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withDSA");
            signature.initSign(privateKey, RANDOM);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new CryptoEngineException("DSA signing failed", e);
        }
    }

    public static boolean verifyDsa(byte[] data, byte[] signatureBytes, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withDSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    // --- ECDSA (secp256r1) ---

    public static KeyPair generateEcdsaKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoEngineException("Failed to generate ECDSA key pair (secp256r1)", e);
        }
    }

    public static byte[] signEcdsa(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey, RANDOM);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new CryptoEngineException("ECDSA signing failed", e);
        }
    }

    public static boolean verifyEcdsa(byte[] data, byte[] signatureBytes, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
