package Decryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.logging.Logger;

public class Decryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final Logger logger  = Logger.getLogger(Decryption.class.getName());


    public static class KeyAndIv {
        public final SecretKey key;
        public final byte[] iv;

        public KeyAndIv(SecretKey key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }
    }

    /**
     * Loads a secret key from a file
     * @param keyFile The file containing the Base64-encoded key
     * @return The loaded secretKet
     * **/


    public static KeyAndIv loadKeyFromFile(String keyFile) throws Exception {
        try{
            var lines = Files.readAllLines(Paths.get(keyFile));
            String base64Key = null;
            String base64Iv = null;
            // Parse key and IV
            for (String line : lines) {
                if (line.startsWith("key:")) {
                    base64Key = line.substring(4).trim();
                } else if (line.startsWith("iv:")) {
                    base64Iv = line.substring(3).trim();
                }
            }
            if (base64Key == null || base64Iv == null) {
                throw new IllegalArgumentException("Invalid key file format");
            }
            //Decode key
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            //Decode IV
            byte[] ivBytes = Base64.getDecoder().decode(base64Iv);

            return new KeyAndIv(secretKey, ivBytes);

            }catch(Exception e){
                throw new Exception("Failed to load key from file: " + e.getMessage(), e);
            }

    }

    /**
     * Decrypt file using AES-GCM
     * @param inputFile
     * @param outputFile
     * @param secretKey
     * @throws Exception
     *
     * */
    public static void decrypt(String inputFile,String outputFile, SecretKey secretKey,GCMParameterSpec ivSpec) throws Exception {
        logger.info("Starting description of file: "+ inputFile);
        try(FileInputStream fis = new FileInputStream(inputFile);
            FileOutputStream fos = new FileOutputStream(outputFile);
        ){
            //Read the IV from the begining of the file
            //IV is a reandom number used alongside the secrey key to ensure encryptin the same plaintext multiple times with
            //the same plaintext multiple times
            byte[] iv = new byte[IV_LENGTH];
            int byteRead = fis.read(iv);
            //verify we read exactly the IV_LENGTH bytes
            if(byteRead != IV_LENGTH)
                throw new IOException("Invalid encrypted file: IV not found");

            //Initialize the cipher with the same parameters used for encryption
            Cipher cipher  = Cipher.getInstance(ALGORITHM);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            //Decrypt the file content
            byte[] buffer = new byte[8192];
            int count;
            while((count = fis.read(buffer)) > 0){
                byte[] output = cipher.update(buffer, 0 , count);
                if(output !=null) fos.write(output);
            }
            //Finalize the decryption
            byte[] output = cipher.doFinal();
            if(output !=null) fos.write(output);

            logger.info("File decrypted successfully: "+ outputFile);

        }
    }

}
