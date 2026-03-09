package org.fascinate.encody;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class Encryptor {

    // --- Constants ---
    private static final int SALT_LENGTH = 16;         // Length of the random salt in bytes
    private static final int IV_LENGTH = 12;           // AES-GCM IV length (12 bytes is standard)
    private static final int KEY_LENGTH = 256;         // AES key length in bits
    private static final int PBKDF2_ITERATIONS = 65536; // Number of iterations for key derivation
    private static final int GCM_TAG_LENGTH = 128;     // GCM authentication tag length in bits

    // ANSI color codes
    public static final String RESET = "\u001B[0m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";

    /**
     * Encrypts a file using AES-GCM with a password.
     * The output file will contain: [SALT][IV][CIPHERTEXT].
     * Deletes the original file after successful encryption.
     *
     * @param file     The input file to encrypt.
     * @param password The password used to derive the encryption key.
     */
    public static void encryptFile(File file, String password) throws Exception {
        // --- Generate a random salt and IV ---
        byte[] salt = randomBytes(SALT_LENGTH);
        byte[] iv = randomBytes(IV_LENGTH);

        // --- Derive AES key from password + salt using PBKDF2 ---
        SecretKey key = deriveKey(password, salt);

        // --- Read entire file content into memory ---
        byte[] plaintext = Files.readAllBytes(file.toPath());

        // --- Initialize AES-GCM cipher ---
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        // --- Encrypt plaintext ---
        byte[] ciphertext = cipher.doFinal(plaintext);

        // --- Prepare output file ---
        File outFile = new File(file.getAbsolutePath() + ".enc.crypt");

        // --- Write salt, IV, and ciphertext to output ---
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            fos.write(salt);        // 16 bytes salt for key derivation during decryption
            fos.write(iv);          // 12 bytes IV for AES-GCM
            fos.write(ciphertext);  // actual encrypted content
        }

        // --- Delete original file after successful encryption ---
        if (!file.delete()) {
            System.err.println(RED + "Warning: Original file could not be deleted!" + RESET);
        }

        System.out.println(GREEN + "Encrypted -> " + outFile.getAbsolutePath() + RESET);
    }

    /**
     * Decrypts a file encrypted by encryptFile.
     * Assumes the file contains [SALT][IV][CIPHERTEXT].
     * Deletes the encrypted file after successful decryption.
     *
     * @param file     The input encrypted file.
     * @param password The password used to derive the decryption key.
     */
    public static void decryptFile(File file, String password) throws Exception {
        // --- Read entire file content into memory ---
        byte[] content = Files.readAllBytes(file.toPath());

        // --- Extract salt, IV, and ciphertext ---
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[content.length - SALT_LENGTH - IV_LENGTH];

        System.arraycopy(content, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(content, SALT_LENGTH, iv, 0, IV_LENGTH);
        System.arraycopy(content, SALT_LENGTH + IV_LENGTH, ciphertext, 0, ciphertext.length);

        // --- Derive AES key using the same salt and password ---
        SecretKey key = deriveKey(password, salt);

        // --- Initialize AES-GCM cipher for decryption ---
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        try {
            // --- Decrypt ciphertext ---
            byte[] plaintext = cipher.doFinal(ciphertext);

            // --- Write decrypted content to original filename ---
            File outFile = new File(file.getAbsolutePath().replace(".enc.crypt", ""));
            Files.write(outFile.toPath(), plaintext);

            // --- Delete the encrypted file after successful decryption ---
            if (!file.delete()) {
                System.err.println(RED + "Warning: Encrypted file could not be deleted!" + RESET);
            }

            System.out.println(GREEN + "Decrypted -> " + outFile.getAbsolutePath() + RESET);
        } catch (javax.crypto.AEADBadTagException e) {
            // This exception occurs if the password/key is wrong
            System.err.println(RED + "Decryption failed: Wrong password or corrupted file!" + RESET);
        }
    }

    /**
     * Derives a SecretKey from a password and salt using PBKDF2-HMAC-SHA256.
     *
     * @param password The password to derive the key from.
     * @param salt     The salt used to prevent precomputed attacks.
     * @return AES SecretKey
     */
    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Generates a secure random byte array.
     *
     * @param length Number of bytes to generate.
     * @return byte array filled with random data
     */
    private static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        new SecureRandom().nextBytes(b);
        return b;
    }
}