import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.swing.*;
import java.awt.*;

public class EncryptDecryptSwingApp extends JFrame {
    private static final String AES_KEY_STRING = "1234567890123456";  // 16-byte key for AES
    private static final String DES_KEY_STRING = "12345678";  // 8-byte key for DES
    private static KeyPair rsaKeyPair;

    // Swing components
    private JTextArea inputTextArea, outputTextArea;
    private JButton encryptAESButton, decryptAESButton, encryptDESButton, decryptDESButton;
    private JButton encryptRSAButton, decryptRSAButton, hashSHA256Button;

    public EncryptDecryptSwingApp() {
        try {
            rsaKeyPair = generateRSAKeyPair();  // Generate RSA key pair on startup
        } catch (Exception e) {
            e.printStackTrace();
        }

        setTitle("Encryption/Decryption App");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        // Input and Output Text areas
        inputTextArea = new JTextArea(5, 40);
        outputTextArea = new JTextArea(5, 40);
        outputTextArea.setEditable(false);

        // Buttons for encryption/decryption
        encryptAESButton = new JButton("Encrypt with AES");
        decryptAESButton = new JButton("Decrypt with AES");
        encryptDESButton = new JButton("Encrypt with DES");
        decryptDESButton = new JButton("Decrypt with DES");
        encryptRSAButton = new JButton("Encrypt with RSA");
        decryptRSAButton = new JButton("Decrypt with RSA");
        hashSHA256Button = new JButton("Hash with SHA-256");

        // Adding components to the frame
        add(new JLabel("Input:"));
        add(new JScrollPane(inputTextArea));
        add(new JLabel("Output:"));
        add(new JScrollPane(outputTextArea));

        add(encryptAESButton);
        add(decryptAESButton);
        add(encryptDESButton);
        add(decryptDESButton);
        add(encryptRSAButton);
        add(decryptRSAButton);
        add(hashSHA256Button);

        // Button actions with try-catch blocks to handle exceptions
        encryptAESButton.addActionListener(e -> encryptAES());
        decryptAESButton.addActionListener(e -> decryptAES());
        encryptDESButton.addActionListener(e -> encryptDES());
        decryptDESButton.addActionListener(e -> decryptDES());
        encryptRSAButton.addActionListener(e -> encryptRSA());
        decryptRSAButton.addActionListener(e -> decryptRSA());
        hashSHA256Button.addActionListener(e -> hashSHA256());
    }

    private void encryptAES() {
        try {
            String input = inputTextArea.getText();
            String encryptedText = encrypt(input, AES_KEY_STRING, "AES");
            outputTextArea.setText(encryptedText);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    private void decryptAES() {
        try {
            String input = inputTextArea.getText();
            String decryptedText = decrypt(input, AES_KEY_STRING, "AES");
            outputTextArea.setText(decryptedText);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    private void encryptDES() {
        try {
            String input = inputTextArea.getText();
            String encryptedText = encrypt(input, DES_KEY_STRING, "DES");
            outputTextArea.setText(encryptedText);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    private void decryptDES() {
        try {
            String input = inputTextArea.getText();
            String decryptedText = decrypt(input, DES_KEY_STRING, "DES");
            outputTextArea.setText(decryptedText);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    private void encryptRSA() {
        try {
            String input = inputTextArea.getText();
            String encryptedText = encryptRSA(input, rsaKeyPair.getPublic());
            outputTextArea.setText(encryptedText);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    private void decryptRSA() {
        try {
            String input = inputTextArea.getText();
            String decryptedText = decryptRSA(input, rsaKeyPair.getPrivate());
            outputTextArea.setText(decryptedText);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    private void hashSHA256() {
        try {
            String input = inputTextArea.getText();
            String hash = hashSHA256(input);
            outputTextArea.setText(hash);
        } catch (Exception e) {
            outputTextArea.setText("Error: " + e.getMessage());
        }
    }

    // AES and DES encryption/decryption
    private static String encrypt(String data, String key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    private static String decrypt(String encryptedData, String key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedData));
    }

    // RSA encryption
    private static String encryptRSA(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // rsa decryption
    private static String decryptRSA(String encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedData));
    }

    // rsa Key Pair generation
    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // SHA-256 hashing
    private static String hashSHA256(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            EncryptDecryptSwingApp app = new EncryptDecryptSwingApp();
            app.setVisible(true);
        });
    }
}
