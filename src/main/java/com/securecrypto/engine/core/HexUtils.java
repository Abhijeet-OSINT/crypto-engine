package com.securecrypto.engine.core;

import java.util.Base64;
import java.util.HexFormat;

/**
 * Utility for HexFormat and Base64 encoding/decoding.
 * Uses JDK 21 HexFormat for modern, high-performance hex conversions.
 */
public final class HexUtils {

    private static final HexFormat HEX_FORMAT = HexFormat.of();
    private static final HexFormat HEX_FORMAT_UPPER = HexFormat.of().withUpperCase();

    private HexUtils() {
        // Utility class
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        return HEX_FORMAT.formatHex(bytes);
    }

    public static String bytesToHexUpper(byte[] bytes) {
        if (bytes == null) return "";
        return HEX_FORMAT_UPPER.formatHex(bytes);
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[0];
        }
        String cleanHex = hex.replaceAll("\\s+", "");
        try {
            return HEX_FORMAT.parseHex(cleanHex);
        } catch (IllegalArgumentException e) {
            throw new CryptoEngineException("Invalid hexadecimal string format: " + hex, e);
        }
    }

    public static String bytesToBase64(byte[] bytes) {
        if (bytes == null) return "";
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] base64ToBytes(String base64) {
        if (base64 == null || base64.isBlank()) {
            return new byte[0];
        }
        try {
            return Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            throw new CryptoEngineException("Invalid Base64 string format: " + base64, e);
        }
    }
}
