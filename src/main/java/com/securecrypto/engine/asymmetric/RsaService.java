package com.securecrypto.engine.asymmetric;

import com.securecrypto.engine.core.CryptoEngineException;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Service for RSA-OAEP (Encryption/Decryption) and RSA-PSS (Digital Signatures).
 * Supports key sizes of 2048 and 3072 bits.
 */
public final class RsaService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private RsaService() {
    }

    public static KeyPair generateRsaKeyPair(int keySizeBits) {
        if (keySizeBits != 2048 && keySizeBits != 3072) {
            throw new IllegalArgumentException("RSA key size must be 2048 or 3072 bits");
        }
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySizeBits, RANDOM);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoEngineException("Failed to generate RSA key pair", e);
        }
    }

    // --- RSA-OAEP Encryption & Decryption ---

    public static byte[] encryptOaep(byte[] plaintext, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("RSA-OAEP encryption failed", e);
        }
    }

    public static byte[] decryptOaep(byte[] ciphertext, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("RSA-OAEP decryption failed", e);
        }
    }

    // --- RSA-PSS Sign & Verify ---

    public static byte[] signPss(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA/PSS");
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    32,
                    1
            );
            signature.setParameter(pssSpec);
            signature.initSign(privateKey, RANDOM);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new CryptoEngineException("RSA-PSS signing failed", e);
        }
    }

    public static boolean verifyPss(byte[] data, byte[] signatureBytes, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA/PSS");
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    32,
                    1
            );
            signature.setParameter(pssSpec);
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
