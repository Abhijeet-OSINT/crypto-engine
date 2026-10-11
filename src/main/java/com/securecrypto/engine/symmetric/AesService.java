package com.securecrypto.engine.symmetric;

import com.securecrypto.engine.core.CryptoEngineException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Service for AES-GCM (128, 192, 256 bits) Authenticated Encryption with Associated Data (AEAD).
 * Utilizes 96-bit (12 bytes) IVs and 128-bit authentication tags.
 */
public final class AesService {

    public static final int GCM_IV_LENGTH = 12; // 96 bits
    public static final int GCM_TAG_LENGTH = 128; // 128 bits
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesService() {
    }

    public static SecretKey generateAesKey(int keySizeBits) {
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw new IllegalArgumentException("AES key size must be 128, 192, or 256 bits");
        }
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySizeBits, RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoEngineException("Failed to generate AES key", e);
        }
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] encryptGcm(byte[] plaintext, SecretKey key, byte[] iv, byte[] aad) {
        if (iv == null || iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException("GCM IV length must be exactly 96 bits (12 bytes)");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("AES-GCM encryption failed", e);
        }
    }

    public static byte[] encryptGcm(byte[] plaintext, SecretKey key, byte[] iv) {
        return encryptGcm(plaintext, key, iv, null);
    }

    public static byte[] decryptGcm(byte[] ciphertext, SecretKey key, byte[] iv, byte[] aad) {
        if (iv == null || iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException("GCM IV length must be exactly 96 bits (12 bytes)");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("AES-GCM decryption failed: " + e.getMessage(), e);
        }
    }

    public static byte[] decryptGcm(byte[] ciphertext, SecretKey key, byte[] iv) {
        return decryptGcm(ciphertext, key, iv, null);
    }
}
