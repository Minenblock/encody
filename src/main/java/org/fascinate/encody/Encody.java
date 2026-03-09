package org.fascinate.encody;

import java.io.File;
import java.nio.file.Files;
import java.util.Scanner;
import javax.swing.JFileChooser;

/**
 * @author Minenblock, Kuhlklay, BlauerPrinz
 */

/**
 * Main class for Encody
 * Handles:
 *  - File selection via JFileChooser
 *  - Password input
 *  - Automatic encryption/decryption detection
 */
public class Encody {

    public static void main(String[] args) throws Exception {

        // --- File chooser dialog ---
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a file to encrypt/decrypt");

        int result = chooser.showOpenDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            System.out.println("No file selected, exiting.");
            return;
        }

        // --- Get selected file ---
        File file = chooser.getSelectedFile();
        System.out.println("Selected file: " + file.getAbsolutePath());

        // --- Optional: read file size for debugging ---
        byte[] data = Files.readAllBytes(file.toPath());
        System.out.println("File size: " + data.length + " bytes");

        // --- Ask user for password ---
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Password: ");
            String password = scanner.nextLine().trim();

            // --- Decide whether to encrypt or decrypt based on filename ---
            if (file.getName().endsWith(".enc.crypt")) {
                // If file ends with .enc.crypt -> decrypt
                Encryptor.decryptFile(file, password);
            } else {
                // Otherwise, encrypt
                Encryptor.encryptFile(file, password);
            }
        }
    }
}