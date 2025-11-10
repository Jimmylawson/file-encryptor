import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.util.Base64;
import java.util.logging.Logger;

public class Decryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static final Logger logger  = Logger.getLogger(Decryption.class.getName());
    /**
     * Loads a secret key from a file
     * @param keyFile The file containing the Base64-encoded key
     * @return The loaded secretKet
     * **/

    public static SecretKey loadKeyFromFile(String keyFile) throws Exception {
        // 1. Read all bytes from file and convert to String
//    (The file contains Base64 text like "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=")
        String base64Key = new String(Files.readAllBytes(new File(keyFile).toPath()));

// 2. Decode the Base64 string back to the original key bytes
//    (Converts "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=" back to the original byte array)
        byte[] decodeKey = Base64.getDecoder().decode(base64Key);

// 3. Create a SecretKey object from the decoded bytes
        SecretKey secretKey = new SecretKeySpec(decodeKey, "AES");

        return secretKey;

    }

    /**
     * Decrypt file using AES-GCM
     * @param inputFile
     * @param outputFile
     * @param secretKey
     * @throws Exception
     *
     * */
    public static void decryptFile(String inputFile,String outputFile, SecretKey secretKey) throws Exception {
        logger.info("Starting description of file: "+ inputFile);
        try(FileInputStream fis = new FileInputStream(inputFile);
            FileOutputStream fos = new FileOutputStream(outputFile)
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
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

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
