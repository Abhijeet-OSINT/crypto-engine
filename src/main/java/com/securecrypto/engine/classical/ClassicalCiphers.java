package com.securecrypto.engine.classical;

import com.securecrypto.engine.core.CryptoEngineException;

/**
 * Service for classical historical ciphers:
 * Caesar Cipher, ROT13, and Vigenère Cipher.
 */
public final class ClassicalCiphers {

    private ClassicalCiphers() {
    }

    // --- Caesar Cipher ---

    public static String encryptCaesar(String text, int shift) {
        if (text == null) return null;
        int normalizedShift = ((shift % 26) + 26) % 26;
        StringBuilder result = new StringBuilder();

        for (char ch : text.toCharArray()) {
            if (Character.isUpperCase(ch)) {
                char shifted = (char) ('A' + (ch - 'A' + normalizedShift) % 26);
                result.append(shifted);
            } else if (Character.isLowerCase(ch)) {
                char shifted = (char) ('a' + (ch - 'a' + normalizedShift) % 26);
                result.append(shifted);
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }

    public static String decryptCaesar(String text, int shift) {
        return encryptCaesar(text, -shift);
    }

    // --- ROT13 ---

    public static String rot13(String text) {
        return encryptCaesar(text, 13);
    }

    // --- Vigenère Cipher ---

    public static String encryptVigenere(String text, String key) {
        if (text == null) return null;
        if (key == null || key.isBlank()) {
            throw new CryptoEngineException("Vigenère keyword cannot be null or empty");
        }

        String cleanKey = key.toUpperCase().replaceAll("[^A-Z]", "");
        if (cleanKey.isEmpty()) {
            throw new CryptoEngineException("Vigenère key must contain at least one alphabetic character");
        }

        StringBuilder result = new StringBuilder();
        int keyIndex = 0;

        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                int shift = cleanKey.charAt(keyIndex % cleanKey.length()) - 'A';
                if (Character.isUpperCase(ch)) {
                    result.append((char) ('A' + (ch - 'A' + shift) % 26));
                } else {
                    result.append((char) ('a' + (ch - 'a' + shift) % 26));
                }
                keyIndex++;
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }

    public static String decryptVigenere(String text, String key) {
        if (text == null) return null;
        if (key == null || key.isBlank()) {
            throw new CryptoEngineException("Vigenère keyword cannot be null or empty");
        }

        String cleanKey = key.toUpperCase().replaceAll("[^A-Z]", "");
        if (cleanKey.isEmpty()) {
            throw new CryptoEngineException("Vigenère key must contain at least one alphabetic character");
        }

        StringBuilder result = new StringBuilder();
        int keyIndex = 0;

        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                int shift = cleanKey.charAt(keyIndex % cleanKey.length()) - 'A';
                if (Character.isUpperCase(ch)) {
                    result.append((char) ('A' + (ch - 'A' - shift + 26) % 26));
                } else {
                    result.append((char) ('a' + (ch - 'a' - shift + 26) % 26));
                }
                keyIndex++;
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }
}
