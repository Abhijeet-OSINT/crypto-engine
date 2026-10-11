package com.securecrypto.engine.symmetric;

import com.securecrypto.engine.core.CryptoEngineException;
import com.securecrypto.engine.core.HexUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Service handling DES, Double-DES (2DES), and Triple-DES (3DES).
 */
public final class DesSuite {

    private static final SecureRandom RANDOM = new SecureRandom();

    private DesSuite() {
    }

    // --- DES Single ---

    public static SecretKey generateDesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(56, RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoEngineException("Failed to generate DES key", e);
        }
    }

    public static byte[] generateIv8() {
        byte[] iv = new byte[8];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] encryptDes(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("DES encryption failed", e);
        }
    }

    public static byte[] decryptDes(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("DES decryption failed", e);
        }
    }

    // --- Double DES (2DES) ---

    public static class DoubleDesKeys {
        public final SecretKey key1;
        public final SecretKey key2;

        public DoubleDesKeys(SecretKey key1, SecretKey key2) {
            this.key1 = key1;
            this.key2 = key2;
        }
    }

    public static DoubleDesKeys generate2DesKeys() {
        return new DoubleDesKeys(generateDesKey(), generateDesKey());
    }

    /**
     * Double DES Encryption: C = Enc_K2(Enc_K1(P))
     */
    public static byte[] encrypt2Des(byte[] plaintext, SecretKey key1, byte[] iv1, SecretKey key2, byte[] iv2) {
        byte[] intermediate = encryptDes(plaintext, key1, iv1);
        return encryptDes(intermediate, key2, iv2);
    }

    /**
     * Double DES Decryption: P = Dec_K1(Dec_K2(C))
     */
    public static byte[] decrypt2Des(byte[] ciphertext, SecretKey key1, byte[] iv1, SecretKey key2, byte[] iv2) {
        byte[] intermediate = decryptDes(ciphertext, key2, iv2);
        return decryptDes(intermediate, key1, iv1);
    }

    // --- Triple DES (3DES) ---

    public static SecretKey generate3DesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            keyGen.init(168, RANDOM); // 168-bit key (3-key Triple DES)
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoEngineException("Failed to generate 3DES key", e);
        }
    }

    public static byte[] encrypt3Des(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("3DES encryption failed", e);
        }
    }

    public static byte[] decrypt3Des(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("3DES decryption failed", e);
        }
    }
}
