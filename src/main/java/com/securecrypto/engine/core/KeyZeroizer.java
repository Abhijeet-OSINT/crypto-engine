package com.securecrypto.engine.core;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.util.Arrays;

/**
 * Key and buffer zeroization utility to wipe sensitive cryptographic material
 * from memory after use.
 */
public final class KeyZeroizer {

    private KeyZeroizer() {
        // Utility class
    }

    public static void zeroize(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    public static void zeroize(char[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, '\0');
        }
    }

    public static void zeroize(SecretKey key) {
        if (key instanceof Destroyable destroyable) {
            try {
                if (!destroyable.isDestroyed()) {
                    destroyable.destroy();
                }
            } catch (DestroyFailedException ignored) {
                // SecretKey standard software implementations might not support destroy()
            }
        }
        try {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                zeroize(encoded);
            }
        } catch (Exception ignored) {
            // Unextractable keys ignore encoded wiping
        }
    }

    public static boolean isZeroized(byte[] buffer) {
        if (buffer == null) return true;
        for (byte b : buffer) {
            if (b != 0) return false;
        }
        return true;
    }
}
