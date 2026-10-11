package com.securecrypto.engine.hashing;

import com.securecrypto.engine.core.CryptoEngineException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Service providing MD5, SHA-1, SHA-2 family, SHA-3 family, and HMAC (HmacSHA256, HmacSHA512).
 */
public final class HashHmacService {

    private static final SecureRandom RANDOM = new SecureRandom();
    public static final String BC_PROVIDER = "BC";

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private HashHmacService() {
    }

    // --- Message Digest Hashes ---

    public static byte[] hashMd5(byte[] input) {
        return digest("MD5", input);
    }

    public static byte[] hashSha1(byte[] input) {
        return digest("SHA-1", input);
    }

    public static byte[] hashSha224(byte[] input) {
        return digest("SHA-224", input);
    }

    public static byte[] hashSha256(byte[] input) {
        return digest("SHA-256", input);
    }

    public static byte[] hashSha512(byte[] input) {
        return digest("SHA-512", input);
    }

    public static byte[] hashSha3_256(byte[] input) {
        return digest("SHA3-256", input);
    }

    public static byte[] hashSha3_512(byte[] input) {
        return digest("SHA3-512", input);
    }

    private static byte[] digest(String algorithm, byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            try {
                MessageDigest md = MessageDigest.getInstance(algorithm, BC_PROVIDER);
                return md.digest(input);
            } catch (Exception ex) {
                throw new CryptoEngineException("Digest algorithm failed: " + algorithm, ex);
            }
        }
    }

    // --- HMAC ---

    public static SecretKey generateHmacKey(String algorithm, int keySizeBits) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keySizeBits, RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            byte[] keyBytes = new byte[keySizeBits / 8];
            RANDOM.nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes, algorithm);
        }
    }

    public static byte[] hmacSha256(byte[] data, SecretKey key) {
        return computeMac("HmacSHA256", data, key);
    }

    public static byte[] hmacSha512(byte[] data, SecretKey key) {
        return computeMac("HmacSHA512", data, key);
    }

    public static byte[] computeMac(String algorithm, byte[] data, SecretKey key) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(key);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoEngineException("HMAC computation failed for " + algorithm, e);
        }
    }
}
