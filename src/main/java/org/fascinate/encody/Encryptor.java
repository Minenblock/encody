package org.fascinate.encody;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.*;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH = 32; // 256‑bit
    private static final int GCM_TAG_LENGTH = 128;

    public static final String RESET = "\u001B[0m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";

    public static void encryptFile(File file, String password) throws Exception {
        byte[] salt = randomBytes(SALT_LENGTH);
        byte[] iv = randomBytes(IV_LENGTH);

        SecretKey key = deriveKeyArgon2(password, salt);

        File outFile = new File(file.getAbsolutePath() + ".enc.crypt");

        try (FileInputStream fis = new FileInputStream(file);
             FileOutputStream fos = new FileOutputStream(outFile)) {

            fos.write(salt);
            fos.write(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, read);
                }
            }
        }

        secureDelete(file);
        System.out.println(GREEN + "Encrypted -> " + outFile.getAbsolutePath() + RESET);
    }

    public static void decryptFile(File file, String password) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];

            fis.read(salt);
            fis.read(iv);

            SecretKey key = deriveKeyArgon2(password, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            File outFile = new File(file.getAbsolutePath().replace(".enc.crypt", ""));

            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(outFile)) {

                byte[] buffer = new byte[8192];
                int read;
                while ((read = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, read);
                }
            }

            secureDelete(file);
            System.out.println(GREEN + "Decrypted -> " + outFile.getAbsolutePath() + RESET);

        } catch (IOException e) {
            Throwable cause = e.getCause();
            if (cause instanceof javax.crypto.AEADBadTagException) {
                System.err.println(RED + "Decryption failed: Wrong password or corrupted file!" + RESET);
            } else {
                throw e; // Andere IO-Fehler weiterwerfen
            }
        }
    }

    private static SecretKey deriveKeyArgon2(String password, byte[] salt) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(1)
                .withMemoryAsKB(131072) // 128 MiB
                .withIterations(3);

        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(builder.build());

        byte[] key = new byte[KEY_LENGTH];
        gen.generateBytes(password.toCharArray(), key);

        return new SecretKeySpec(key, "AES");
    }

    private static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static void secureDelete(File file) {
        if (!file.exists()) return;
        
        try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
            long len = raf.length();
            byte[] buffer = new byte[8192];
            SecureRandom rnd = new SecureRandom();
            long pos = 0;

            while (pos < len) {
                int writeLen = (int) Math.min(buffer.length, len - pos);
                rnd.nextBytes(buffer);
                raf.seek(pos);
                raf.write(buffer, 0, writeLen);
                pos += writeLen;
            }
            raf.getFD().sync(); // Flush wirklich auf die Platte
        } catch (IOException e) {
            System.err.println(RED + "Secure delete error: " + e.getMessage() + RESET);
        }

        // Datei löschen
        if (!file.delete()) {
            System.err.println(RED + "Warning: Could not delete file!" + RESET);
        }
    }
}