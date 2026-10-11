package com.securecrypto.engine.core;

/**
 * Unified runtime exception wrapper for all cryptographic errors in the engine.
 * Ensures that low-level cryptographic checked exceptions are handled smoothly
 * without breaking application execution boundaries.
 */
public class CryptoEngineException extends RuntimeException {

    public CryptoEngineException(String message) {
        super(message);
    }

    public CryptoEngineException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoEngineException(Throwable cause) {
        super(cause.getMessage(), cause);
    }
}
