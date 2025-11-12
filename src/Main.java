import Decryption.Decryption;
import Encryption.Encryptor;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;
import java.util.logging.Logger;

public class Main{
    private static final Scanner in  = new Scanner(System.in);
    private static final Logger logger = Logger.getLogger(Main.class.getName());
    public static void main(String[] args) {
       try{
           while(true){
               printMenu();
               int choice  = in.nextInt();
               in.nextLine(); //consume newline
               switch(choice){
                   case 1:
                       System.out.print("Enter the path of the file to encrypt: ");
                       String fileToEncrypt = in.nextLine().trim();
                       encryptFile(in, Path.of(fileToEncrypt));
                       break;
                   case 2 :
                       createAndEcryptFile(in);
                       break;
                   case 3:
                       decryptFile();
                       break;
                   default:
                       System.out.println("Existing...");
                       return;
               }
           }
       }catch(Exception ex){
           System.out.println("An error occurred:  " + ex.getMessage());
           ex.printStackTrace();
       }
    }
    static void printMenu(){
        System.out.println("""
                \n🔐File Encryption Menu
                1. Encrypt an existing file
                2. Create and encrypt a new file with a message
                3. Decrypt a file
                4.Exit
                "Enter your choice (1-4): "
                
                """);
    }

    static void createAndEcryptFile(Scanner scanner) throws Exception{
        System.out.print("Enter the name for the new file (e.g., secret.txt): ");
        String fileName = scanner.nextLine().trim();
        System.out.println("Enter your secret message (press Enter then Ctrl+D when done): ");
        String line;
        StringBuilder builder = new StringBuilder();

        while(scanner.hasNextLine()){
            line = scanner.nextLine();
            if(line.isEmpty()) break; // Stop on empty line
            builder.append(line).append("\n");
        }

        //Create a file
        var filePath = Path.of(fileName);
        Files.writeString(filePath, builder.toString());
        logger.info("File created successfully: " + filePath);
        System.out.println("File created: " + filePath.toAbsolutePath());

        //Now encrypt it
        encryptFile(in, filePath);


    }


    /**
     * Encrypts a file using AES-GCM encryption.
     * @param scanner
     * @param inputPath
     * @throws Exception
     */
    static void encryptFile(Scanner scanner, Path inputPath ) throws Exception {
//        //Implementation will come here
//        System.out.print("Enter the file you want to encrypt: ");
//        String inputPath = in.nextLine().trim();
//        File inputFile = new File(inputPath);

        // check if file exist
        if(!Files.exists(inputPath)){
            System.out.println("❌ Error: File not found: " + inputPath.toAbsolutePath());
        }
        //Generate file path
        String output = inputPath + ".enc";

        //Generate key and IV
        GenerateSecretKey keyGen  = new GenerateSecretKey();
        SecretKey secretKey = keyGen.generateKeyGenerator(256);
        var ivSpec = GenerateSecretKey.generateIv();
        byte[] iv = ivSpec.getIV();

        //Save key to a file
        String keyFile = "aes_" + inputPath.getFileName() + ".key";
        Encryptor.saveKeyAndIv(keyFile, secretKey, ivSpec);

        System.out.println("\n✅ Encryption successful");
        System.out.println("   - Encrypted file: " + new File(output).getAbsolutePath());
        System.out.println("   - Key file: " + new File(keyFile).getAbsolutePath());

        //Encrypt a file
        String outputPath = inputPath + ".enc";
        Encryptor.ecrypt(inputPath.toString(), outputPath, secretKey, ivSpec);

        logger.info("IV used for encryption: " + new String(iv));
        System.out.println("File encrypted successfully: " + outputPath);

    }

    /**
     * Decrypts an encrypted file using the provided key file.
     * @throws Exception if there is an error decrypting the file
     */
    static void decryptFile() {
        try {
            System.out.print("Enter the path of the encrypted file: ");
            String inputPath = in.nextLine().trim();
            System.out.print("Enter the path of the key file: ");
            String keyFile = in.nextLine().trim();

            // Load both key and IV
            Decryption.KeyAndIv keyAndIv = Decryption.loadKeyFromFile(keyFile);
            SecretKey secretKey = keyAndIv.key;


            // Create output path (remove .enc if present)
            String outputPath = inputPath.endsWith(".enc")
                    ? inputPath.substring(0, inputPath.length() - 4)
                    : inputPath + ".dec";

            // Decrypt the file
            Decryption.decrypt(inputPath, outputPath, keyAndIv.key, new GCMParameterSpec(128, keyAndIv.iv));

            System.out.println("\n✅ Decryption successful");
            System.out.println("   - Decrypted file: " + new File(outputPath).getAbsolutePath());

        } catch (Exception e) {
            System.out.println("\n❌ Error during decryption: " + e.getMessage());
            logger.severe("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}