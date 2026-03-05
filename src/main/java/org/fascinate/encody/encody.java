package org.fascinate.encody;

import java.io.File;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.swing.JFileChooser;

/**
 *
 * @author Minenblock, Kuhlklay, BlauerPrinz
 */
public class Encody {

    public static void main(String[] args) throws Exception {

        // --- Datei-Auswahl-Dialog ---
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a file to hash");

        int result = chooser.showOpenDialog(null);

        if (result != JFileChooser.APPROVE_OPTION) {
            System.out.println("No file selected, exiting.");
            return;
        }

        File file = chooser.getSelectedFile();
        System.out.println("Selected file: " + file.getAbsolutePath());

        byte[] data = Files.readAllBytes(file.toPath());
        System.out.println("File size: " + data.length + " bytes");

        // --- Passwort eingeben ---
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Password: ");
            String input = scanner.nextLine().trim();

            // --- 8-Byte Salt erzeugen ---
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);

            StringBuilder salt_builder = new StringBuilder();
            for (byte b : bytes) {
                salt_builder.append(String.format("%02x", b & 0xFF));
            }
            String salt = salt_builder.toString();

            System.out.println("Salt: 0x" + salt);

            // --- Hash generieren ---
            System.out.println("Hash: 0x" + Hasher.hash(input, salt));
        }
    }
}