package org.fascinate.encody;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Encryptor class provides file encryption and decryption using AES-GCM with
 * Argon2-derived keys. Secure deletion of plaintext files is also implemented.
 * 
 * Design decisions:
 * - AES-GCM is chosen for authenticated encryption (confidentiality + integrity).
 * - Argon2id is used for password-based key derivation (memory-hard, resistant to GPU attacks).
 * - FileChannel with ByteBuffer is used for efficient streaming of large files.
 * - SecureRandom is used for cryptographic randomness.
 * - ThreadLocal is used for Cipher and Argon2BytesGenerator to allow reuse and avoid repeated instantiation.
 */
public class Encryptor {

    // --- Constants defining encryption parameters ---
    private static final int SALT_LENGTH = 16;          // Salt for Argon2, standard 128-bit
    private static final int IV_LENGTH = 12;            // AES-GCM IV (nonce), recommended 96-bit
    private static final int KEY_LENGTH = 32;           // AES-256 key length in bytes
    private static final int GCM_TAG_LENGTH = 128;      // Authentication tag length in bits
    private static final int AES_MEMORY = 128 * 1024;   // Authentication tag length in bits

    private static final int BUFFER_SIZE = 2 * 1024 * 1024;         // 2 MB buffer for file streaming
    private static final SecureRandom RANDOM = new SecureRandom();  // Strong random number generator

    // Thread-local Cipher to ensure thread-safety without re-instantiation overhead
    private static final ThreadLocal<Cipher> AES_GCM = ThreadLocal.withInitial(() -> {
        try { 
            // Register Bouncy Castle if not present
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            // Using "BC" provider is critical to bypass the 2GB limit found in standard SunJCE
            return Cipher.getInstance("AES/GCM/NoPadding", "BC"); 
        } catch (Exception e) { 
            throw new RuntimeException("Failed to initialize cryptographic provider", e); 
        }
    });

    // Thread-local Argon2 generator to avoid repeated instantiation
    private static final ThreadLocal<Argon2BytesGenerator> ARGON2 = ThreadLocal.withInitial(Argon2BytesGenerator::new);

    // ANSI color codes for console output
    public static final String RESET = "\u001B[0m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";

    private static class FileBuffers {
        final ByteBuffer inBuffer;
        final byte[] tempArray;
        final byte[] outArray;

        FileBuffers(int bufferSize, Cipher cipher) {
            this.inBuffer = ByteBuffer.allocate(bufferSize);
            this.tempArray = new byte[bufferSize];
            this.outArray = new byte[cipher.getOutputSize(bufferSize) + 128];
        }
    }

    /**
     * Allocates efficient buffers depending on file size.
     * - Splitting into 2MB chunks for efficiency.
     */
    private static FileBuffers allocateBuffers(File file, Cipher cipher) {
        return new FileBuffers(BUFFER_SIZE, cipher); // Fixe 2 MB Puffer
    }

    /**
     * Encrypts a file using AES-GCM with a key derived from the given password.
     * The encrypted file will have ".enc.crypt" appended to its name.
     * 
     * @param file     The file to encrypt
     * @param password The password to derive the encryption key
     * @throws Exception if encryption fails
     */
    public static void encryptFile(File file, String password) throws Exception {
        // Generate cryptographically strong salt and IV
        byte[] salt = randomBytes(SALT_LENGTH);
        byte[] iv = randomBytes(IV_LENGTH);

        // Derive AES key from password using Argon2id
        SecretKey key = deriveKeyArgon2(password, salt);

        File outFile = new File(file.getAbsolutePath() + ".enc.crypt");

        // Use FileChannel for efficient streaming of large files
        try (FileChannel inChannel = FileChannel.open(file.toPath(), StandardOpenOption.READ);
             FileChannel outChannel = FileChannel.open(outFile.toPath(),
                     StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {

            // Write salt and IV at the beginning of the output file for decryption
            outChannel.write(ByteBuffer.wrap(salt));
            outChannel.write(ByteBuffer.wrap(iv));

            // Initialize AES-GCM cipher for encryption
            Cipher cipher = AES_GCM.get();
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            // Allocate a heap buffer to read the file in chunks
            ByteBuffer inBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            ByteBuffer outBuffer = ByteBuffer.allocate(cipher.getOutputSize(BUFFER_SIZE));

            // Read the input file in chunks, encrypt, and write to output file
            long totalBytes = file.length();
            long processed = 0;

            while (inChannel.read(inBuffer) != -1) {
                inBuffer.flip();
                int len = inBuffer.remaining(); // number of bytes read

                cipher.update(inBuffer, outBuffer);

                outBuffer.flip();
                outChannel.write(outBuffer);
                outBuffer.clear();

                processed += len; // update progress
                System.out.printf("Decrypting: %.2f%%\r", 100.0 * processed / totalBytes);

                inBuffer.clear();
            }

            byte[] finalBytes = cipher.doFinal();
            if (finalBytes.length > 0) outChannel.write(ByteBuffer.wrap(finalBytes));
            System.out.println();
        }

        // Securely delete the original plaintext file
        secureDelete(file);
        System.out.println(GREEN + "Encrypted -> " + outFile.getAbsolutePath() + RESET);
    }

    /**
     * Decrypts a file previously encrypted with encryptFile().
     * The output file will have the ".enc.crypt" suffix removed.
     * 
     * @param file     The encrypted file
     * @param password The password to derive the decryption key
     * @throws Exception if decryption fails
     */
    public static void decryptFile(File file, String password) throws Exception {
        // Temporary file to write decrypted content
        File tempFile = new File(file.getAbsolutePath() + ".tmp");

        try (FileChannel inChannel = FileChannel.open(file.toPath(), StandardOpenOption.READ);
             FileChannel outChannel = FileChannel.open(tempFile.toPath(),
                     StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {

            // Read salt and IV from the start of the file
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];

            if (inChannel.read(ByteBuffer.wrap(salt)) != SALT_LENGTH ||
                inChannel.read(ByteBuffer.wrap(iv)) != IV_LENGTH) {
                throw new IOException("Invalid encrypted file");
            }

            // Derive AES key from password and salt
            SecretKey key = deriveKeyArgon2(password, salt);

            // Initialize AES-GCM cipher for decryption
            Cipher cipher = AES_GCM.get();
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            // Heap buffer for reading the encrypted file in chunks
            ByteBuffer inBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            ByteBuffer outBuffer = ByteBuffer.allocate(cipher.getOutputSize(BUFFER_SIZE) + 128); // 128 bytes for padding

            // Process each chunk
            long totalBytes = file.length() - SALT_LENGTH - IV_LENGTH;
            long processed = 0;

            while (inChannel.read(inBuffer) != -1) {
                inBuffer.flip();
                int len = inBuffer.remaining(); // number of bytes read

                cipher.update(inBuffer, outBuffer);

                outBuffer.flip();
                outChannel.write(outBuffer);
                outBuffer.clear();

                processed += len; // update progress
                System.out.printf("Decrypting: %.2f%%\r", 100.0 * processed / totalBytes);

                inBuffer.clear();
            }

            byte[] finalBytes = cipher.doFinal();
            if (finalBytes.length > 0) outChannel.write(ByteBuffer.wrap(finalBytes));
            System.out.println();
        } catch (Exception e) {
            tempFile.delete(); // Clean up temporary file if decryption fails

            // Check for authentication failure
            Throwable cause = e;
            while (cause != null) {
                if (cause instanceof javax.crypto.AEADBadTagException) {
                    System.err.println(RED + "Wrong password or corrupted file!" + RESET);
                    return;
                }
                cause = cause.getCause();
            }
            throw e;
        }

        // Move temporary file to final decrypted file
        File outFile = new File(file.getAbsolutePath().replace(".enc.crypt", ""));
        Files.move(tempFile.toPath(), outFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);

        // Securely delete the encrypted file
        secureDelete(file);
        System.out.println(GREEN + "Decrypted -> " + outFile.getAbsolutePath() + RESET);
    }

    /**
     * Derives a 256-bit AES key from a password using Argon2id.
     * Memory- and CPU-intensive to resist brute-force attacks.
     */
    private static SecretKey deriveKeyArgon2(String password, byte[] salt) {
        int cores = Runtime.getRuntime().availableProcessors();

        // Argon2id parameters: memory=AES_MEMORY, iterations=3, parallelism=min(cores, 4)
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(Math.min(4, cores))
                .withMemoryAsKB(AES_MEMORY)
                .withIterations(3);

        Argon2BytesGenerator gen = ARGON2.get();
        gen.init(builder.build());

        byte[] key = new byte[KEY_LENGTH];
        gen.generateBytes(password.toCharArray(), key);

        return new SecretKeySpec(key, "AES");
    }

    /**
     * Generates cryptographically secure random bytes.
     */
    private static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        RANDOM.nextBytes(b);
        return b;
    }

    /**
     * Securely deletes a file by overwriting it with random data before removing it.
     * Uses FileChannel with ByteBuffer for efficiency.
     */
    private static void secureDelete(File file) {
        if (!file.exists()) return;
        try {
            byte[] random = new byte[(int) Math.min(file.length(), 64 * 1024)]; // max 64KB
            RANDOM.nextBytes(random);
            Files.write(file.toPath(), random); // überschreiben
            file.delete();
        } catch (IOException e) {
            System.err.println(RED + "Secure delete error: " + e.getMessage() + RESET);
        }
    }
}