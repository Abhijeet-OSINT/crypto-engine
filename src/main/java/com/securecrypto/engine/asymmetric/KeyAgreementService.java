package com.securecrypto.engine.asymmetric;

import com.securecrypto.engine.core.CryptoEngineException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Service for Finite-Field Diffie-Hellman (DH Groups 14 & 15) and
 * Elliptic-Curve Diffie-Hellman (ECDH over secp256r1).
 */
public final class KeyAgreementService {

    private static final SecureRandom RANDOM = new SecureRandom();

    // RFC 3526 2048-bit MODP Group 14 Prime
    public static final BigInteger DH_GROUP14_P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E1C7E1447A526F076B65A759C304400593B07" +
            "CCE2EB17251D9D28676DE23E63B439D765E2E0C46709A0B5" +
            "026C2D16709FE68945727A0026D47679058F691C50E5D53E" +
            "59E4EC7396759B3414E87E7B22C4DE9BE621321B4C78370F" +
            "52C1321435B396124709C0C40546643BFFFFFFFFFFFFFFFF", 16
    );

    // RFC 3526 3072-bit MODP Group 15 Prime
    public static final BigInteger DH_GROUP15_P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E1C7E1447A526F076B65A759C304400593B07" +
            "CCE2EB17251D9D28676DE23E63B439D765E2E0C46709A0B5" +
            "026C2D16709FE68945727A0026D47679058F691C50E5D53E" +
            "59E4EC7396759B3414E87E7B22C4DE9BE621321B4C78370F" +
            "52C1321435B3961213EC0DF19004B9E99A5734A454273380" +
            "CE0B9174A369A1730540D3CD3A431B302B0A6DF25F14374F" +
            "E1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0B" +
            "FF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649" +
            "286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69" +
            "163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9E" +
            "D529077096966D670C354E4ABC9804F1746C08CA18217C32" +
            "905E462E36CE3BE39E772C180E1C7E1447A526F076B65A75" +
            "9C304400593B07CCE2EB17251D9D28676DE23E63B439D765" +
            "E2E0C46709A0B5026C2D16709FE68945727A0026D4767905" +
            "8F691C50E5D53E59E4EC7396759B3414E87E7B22C4DE9BE6" +
            "21321B4C78370F52C1321435B396124709C0C40546643BFF" +
            "FFFFFFFFFFFFFFFF", 16
    );

    public static final BigInteger DH_G = BigInteger.valueOf(2);

    private KeyAgreementService() {
    }

    // --- Finite Field Diffie-Hellman ---

    public static KeyPair generateDhKeyPairGroup14() {
        return generateDhKeyPair(DH_GROUP14_P, DH_G);
    }

    public static KeyPair generateDhKeyPairGroup15() {
        return generateDhKeyPair(DH_GROUP15_P, DH_G);
    }

    public static KeyPair generateDhKeyPair(BigInteger p, BigInteger g) {
        try {
            DHParameterSpec dhParamSpec = new DHParameterSpec(p, g);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhParamSpec, RANDOM);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoEngineException("Failed to generate DH key pair", e);
        }
    }

    public static byte[] deriveDhSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(peerPublicKey, true);
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            throw new CryptoEngineException("DH shared secret derivation failed", e);
        }
    }

    // --- ECDH (Elliptic-Curve Diffie-Hellman) ---

    public static KeyPair generateEcdhKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoEngineException("Failed to generate ECDH key pair (secp256r1)", e);
        }
    }

    public static byte[] deriveEcdhSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(peerPublicKey, true);
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            throw new CryptoEngineException("ECDH shared secret derivation failed", e);
        }
    }
}
