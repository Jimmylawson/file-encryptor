package Encryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Logger;

public class Encryptor {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;  // Using 256-bit keys
    private static final int IV_LENGTH = 12;  // 12 bytes for GCM IV
    private static final int TAG_LENGTH = 128; // 128-bit authentication tag

    /**
     * Encrypts a file using AES-GCM
     * @param inputFile The file to encrypt
     * @param outputFile Where to save the encrypted file
     * @param secretKey The secret key for encryption
     * @return The IV used for encryption (needed for decryption)
     */

    public static byte[] ecrypt(String inputFile, String outputFile, SecretKey secretKey, GCMParameterSpec gcmParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        // Generate a random IV
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // Write IV to the beginning of the output file
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             FileInputStream fis = new FileInputStream(inputFile)) {

            // Write IV first
            fos.write(iv);


            // Encrypt the file content
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = fis.read(buffer)) > 0) {
                    cos.write(buffer, 0, count);
                }
            }

        return iv;  // Return IV for decryption

        }

    }
    /**
     * Saves the secret key to a file in Base64 format
     * @param secretKey The secret key to save
     * @param keyFile The file path where to save the key
     * @param gcmSpec The GCMParameterSpec containing the IV
     * @throws RuntimeException if there's an error writing to the file
     */
    public static void saveKeyAndIv(String keyFile,SecretKey secretKey,GCMParameterSpec gcmSpec) {
        Logger logger = Logger.getLogger(Encryptor.class.getName());
        logger.info("Saving file to file: "+ keyFile);

        try (FileWriter writer = new FileWriter(keyFile)) {
            // Convert the key and IV to Base64 string
            String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            String base64Iv = Base64.getEncoder().encodeToString(gcmSpec.getIV());

            // Write the Base64-encoded key to the file
            writer.write("key: " + base64Key + System.lineSeparator() + "iv: " + base64Iv);
            logger.info("Successfully saved key and IV to: " + keyFile);
        } catch (IOException e) {
            throw new RuntimeException("Failed to save key to file: " + e.getMessage(), e);
        }
    }
}
