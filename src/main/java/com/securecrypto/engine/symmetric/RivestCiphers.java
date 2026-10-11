package com.securecrypto.engine.symmetric;

import com.securecrypto.engine.core.CryptoEngineException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Service providing RC4, RC5, and RC6 ciphers via Bouncy Castle Provider.
 */
public final class RivestCiphers {

    private static final SecureRandom RANDOM = new SecureRandom();
    public static final String BC_PROVIDER = "BC";

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private RivestCiphers() {
    }

    // --- RC4 Stream Cipher ---

    public static SecretKey generateRc4Key(int keySizeBytes) {
        byte[] keyBytes = new byte[keySizeBytes];
        RANDOM.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "RC4");
    }

    public static byte[] encryptRc4(byte[] plaintext, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RC4", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("RC4 encryption failed", e);
        }
    }

    public static byte[] decryptRc4(byte[] ciphertext, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RC4", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("RC4 decryption failed", e);
        }
    }

    // --- RC5 Block Cipher ---

    public static SecretKey generateRc5Key(int keySizeBytes) {
        byte[] keyBytes = new byte[keySizeBytes];
        RANDOM.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "RC5");
    }

    public static byte[] generateIv8() {
        byte[] iv = new byte[8];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] encryptRc5(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("RC5/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("RC5 encryption failed", e);
        }
    }

    public static byte[] decryptRc5(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("RC5/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("RC5 decryption failed", e);
        }
    }

    // --- RC6 Block Cipher ---

    public static SecretKey generateRc6Key(int keySizeBytes) {
        byte[] keyBytes = new byte[keySizeBytes];
        RANDOM.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "RC6");
    }

    public static byte[] generateIv16() {
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] encryptRc6(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("RC6/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("RC6 encryption failed", e);
        }
    }

    public static byte[] decryptRc6(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("RC6/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("RC6 decryption failed", e);
        }
    }
}
