package com.securecrypto.engine.pqc;

import com.securecrypto.engine.core.CryptoEngineException;
import com.securecrypto.engine.symmetric.AesService;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KEM;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * Service implementing ML-KEM-768 (FIPS 203) Key Encapsulation Mechanism and
 * Post-Quantum Hybrid Envelope Encryption (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM + AAD).
 *
 * Wire Format:
 * [kemCtLen (4B)] + [kemCt] + [iv (12B)] + [aadLen (4B)] + [aad] + [aesCt]
 */
public final class HybridPqcService {

    public static final String BC_PROVIDER = "BC";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] HKDF_SALT = "SECURECRYPTO-MLKEM-768-SALT".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO = "SECURECRYPTO-AES-256-GCM-KEY".getBytes(StandardCharsets.UTF_8);

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private HybridPqcService() {
    }

    // --- ML-KEM Key Pair Generation ---

    public static KeyPair generateMlKem768KeyPair() {
        try {
            KeyPairGenerator keyGen;
            try {
                keyGen = KeyPairGenerator.getInstance("ML-KEM-768", BC_PROVIDER);
            } catch (Exception e) {
                keyGen = KeyPairGenerator.getInstance("ML-KEM", BC_PROVIDER);
                keyGen.initialize(MLKEMParameterSpec.ml_kem_768, RANDOM);
            }
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber768", BC_PROVIDER);
                return keyGen.generateKeyPair();
            } catch (Exception ex) {
                throw new CryptoEngineException("Failed to generate ML-KEM-768 key pair", ex);
            }
        }
    }

    // --- ML-KEM Encapsulation & Decapsulation ---

    public static class MlKemEncapsulationResult {
        public final SecretKey sharedSecret;
        public final byte[] encapsulationCiphertext;

        public MlKemEncapsulationResult(SecretKey sharedSecret, byte[] encapsulationCiphertext) {
            this.sharedSecret = sharedSecret;
            this.encapsulationCiphertext = encapsulationCiphertext;
        }
    }

    private static KEM getKemInstance(String preferredAlg) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (preferredAlg != null && !preferredAlg.isBlank()) {
            try {
                return KEM.getInstance(preferredAlg, BC_PROVIDER);
            } catch (Exception ignored) {
                try {
                    return KEM.getInstance(preferredAlg);
                } catch (Exception ignored2) {
                }
            }
        }
        for (String alg : new String[]{"ML-KEM-768", "ML-KEM", "Kyber768", "Kyber"}) {
            try {
                return KEM.getInstance(alg, BC_PROVIDER);
            } catch (Exception ignored) {
                try {
                    return KEM.getInstance(alg);
                } catch (Exception ignored2) {
                }
            }
        }
        throw new NoSuchAlgorithmException("No KEM provider found for " + preferredAlg);
    }

    public static MlKemEncapsulationResult encapsulateMlKem768(PublicKey publicKey) {
        try {
            KEM kem = getKemInstance(publicKey.getAlgorithm());
            KEM.Encapsulator encapsulator = kem.newEncapsulator(publicKey, null, RANDOM);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();
            return new MlKemEncapsulationResult(encapsulated.key(), encapsulated.encapsulation());
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : (e.getCause() != null ? e.getCause().getMessage() : e.getClass().getSimpleName());
            throw new CryptoEngineException("ML-KEM-768 encapsulation failed (" + msg + ")", e);
        }
    }

    public static SecretKey decapsulateMlKem768(PrivateKey privateKey, byte[] encapsulationCiphertext) {
        try {
            KEM kem = getKemInstance(privateKey.getAlgorithm());
            KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
            return decapsulator.decapsulate(encapsulationCiphertext);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : (e.getCause() != null ? e.getCause().getMessage() : e.getClass().getSimpleName());
            throw new CryptoEngineException("ML-KEM-768 decapsulation failed (" + msg + ")", e);
        }
    }

    // --- RFC 5869 HKDF-SHA256 ---

    public static byte[] hkdfSha256ExtractAndExpand(byte[] ikm, byte[] salt, byte[] info, int lengthBytes) {
        try {
            byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
            SecretKeySpec saltKey = new SecretKeySpec(actualSalt, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(saltKey);
            byte[] prk = mac.doFinal(ikm);

            // Expand
            SecretKeySpec prkKey = new SecretKeySpec(prk, "HmacSHA256");
            ByteArrayOutputStream okm = new ByteArrayOutputStream();
            byte[] t = new byte[0];
            int counter = 1;

            while (okm.size() < lengthBytes) {
                mac.init(prkKey);
                mac.update(t);
                if (info != null && info.length > 0) {
                    mac.update(info);
                }
                mac.update((byte) counter);
                t = mac.doFinal();
                int bytesToWrite = Math.min(t.length, lengthBytes - okm.size());
                okm.write(t, 0, bytesToWrite);
                counter++;
            }
            return okm.toByteArray();
        } catch (Exception e) {
            throw new CryptoEngineException("HKDF-SHA256 derivation failed", e);
        }
    }

    // --- Hybrid PQC Envelope Encryption & Decryption ---

    /**
     * Encrypts payload into hybrid envelope format:
     * [kemCtLen (4B)] + [kemCt] + [iv (12B)] + [aadLen (4B)] + [aad] + [aesCt]
     */
    public static byte[] encryptHybridEnvelope(byte[] plaintext, PublicKey recipientPublicKey, byte[] aad) {
        try {
            // 1. ML-KEM-768 Encapsulation
            MlKemEncapsulationResult kemResult = encapsulateMlKem768(recipientPublicKey);
            byte[] ikm = kemResult.sharedSecret.getEncoded();

            // 2. HKDF-SHA256 Key Derivation for AES-256
            byte[] aesKeyBytes = hkdfSha256ExtractAndExpand(ikm, HKDF_SALT, HKDF_INFO, 32);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // 3. AES-256-GCM Encryption
            byte[] iv = AesService.generateIv();
            byte[] actualAad = (aad == null) ? new byte[0] : aad;
            byte[] aesCt = AesService.encryptGcm(plaintext, aesKey, iv, actualAad);

            // 4. Pack wire format
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeInt(kemResult.encapsulationCiphertext.length);
            dos.write(kemResult.encapsulationCiphertext);
            dos.write(iv);
            dos.writeInt(actualAad.length);
            dos.write(actualAad);
            dos.write(aesCt);

            dos.flush();
            return baos.toByteArray();
        } catch (CryptoEngineException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoEngineException("Hybrid PQC envelope encryption failed", e);
        }
    }

    /**
     * Decrypts hybrid envelope wire format.
     */
    public static byte[] decryptHybridEnvelope(byte[] wireFormat, PrivateKey recipientPrivateKey) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(wireFormat);
            DataInputStream dis = new DataInputStream(bais);

            int kemCtLen = dis.readInt();
            byte[] kemCt = new byte[kemCtLen];
            dis.readFully(kemCt);

            byte[] iv = new byte[AesService.GCM_IV_LENGTH];
            dis.readFully(iv);

            int aadLen = dis.readInt();
            byte[] aad = new byte[aadLen];
            dis.readFully(aad);

            byte[] aesCt = dis.readAllBytes();

            // 1. ML-KEM-768 Decapsulation
            SecretKey sharedSecret = decapsulateMlKem768(recipientPrivateKey, kemCt);
            byte[] ikm = sharedSecret.getEncoded();

            // 2. HKDF-SHA256 Key Derivation for AES-256
            byte[] aesKeyBytes = hkdfSha256ExtractAndExpand(ikm, HKDF_SALT, HKDF_INFO, 32);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // 3. AES-256-GCM Decryption
            return AesService.decryptGcm(aesCt, aesKey, iv, aad);
        } catch (CryptoEngineException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoEngineException("Hybrid PQC envelope decryption failed", e);
        }
    }
}
