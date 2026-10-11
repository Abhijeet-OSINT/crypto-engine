package com.securecrypto.engine.symmetric;

import com.securecrypto.engine.core.CryptoEngineException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Service providing Blowfish, Twofish, and IDEA block ciphers via Bouncy Castle Provider.
 */
public final class BlockCiphers {

    private static final SecureRandom RANDOM = new SecureRandom();
    public static final String BC_PROVIDER = "BC";

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private BlockCiphers() {
    }

    // --- Blowfish ---

    public static SecretKey generateBlowfishKey(int keySizeBits) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish", BC_PROVIDER);
            keyGen.init(keySizeBits, RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new CryptoEngineException("Failed to generate Blowfish key", e);
        }
    }

    public static byte[] generateIv8() {
        byte[] iv = new byte[8];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] generateIv16() {
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] encryptBlowfish(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("Blowfish encryption failed", e);
        }
    }

    public static byte[] decryptBlowfish(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("Blowfish decryption failed", e);
        }
    }

    // --- Twofish ---

    public static SecretKey generateTwofishKey(int keySizeBits) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("Twofish", BC_PROVIDER);
            keyGen.init(keySizeBits, RANDOM);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new CryptoEngineException("Failed to generate Twofish key", e);
        }
    }

    public static byte[] encryptTwofish(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("Twofish/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("Twofish encryption failed", e);
        }
    }

    public static byte[] decryptTwofish(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("Twofish/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("Twofish decryption failed", e);
        }
    }

    // --- IDEA ---

    public static SecretKey generateIdeaKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("IDEA", BC_PROVIDER);
            keyGen.init(128, RANDOM); // IDEA standard 128-bit key
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new CryptoEngineException("Failed to generate IDEA key", e);
        }
    }

    public static byte[] encryptIdea(byte[] plaintext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("IDEA/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoEngineException("IDEA encryption failed", e);
        }
    }

    public static byte[] decryptIdea(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("IDEA/CBC/PKCS7Padding", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoEngineException("IDEA decryption failed", e);
        }
    }
}
