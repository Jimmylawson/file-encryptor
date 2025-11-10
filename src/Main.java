import javax.crypto.SecretKey;
import java.io.File;
import java.security.NoSuchAlgorithmException;
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
                   case 1 -> encryptFile();
                   case 2-> decryptFile();
                   case 3->{
                       System.out.println("Existing...");
                       return;
                   }
                   default -> System.out.println("Invalid choice. Please try again.");
               }
           }
       }catch(Exception ex){
           System.out.println("An error occurred:  " + ex.getMessage());
           ex.printStackTrace();
       }
    }
    static void printMenu(){
        System.out.println("""
                \nFile Encryption Menu
                1. Encrypt File
                2. Decrypt File
                3. Exit
                "Enter your choice: "
                
                """);
    }
    static void encryptFile() throws Exception {
        //Implementation will come here
        System.out.println("Enter the file you want to encrypt");
        String inputPath = in.nextLine().trim();
        File inputFile = new File(inputPath);

        if(!inputFile.exists()){
            System.out.println("Error: Input file does not exist. ");
            return;
        }
        //Generate a new Key
        var keyGenerator = new GenerateSecretKey();
        SecretKey secretKey = keyGenerator.generateKeyGenerator(256);

        //Save key to a file
        String keyFile = "aes.key";
        Encryptor.saveKeyToFile(secretKey, keyFile);
        System.out.println("Key saved to: " + keyFile);

        //Encrypt a file
        String outputPath = inputPath + ".enc";
        byte[] iv  = Encryptor.ecrypt(inputPath, outputPath, secretKey, GenerateSecretKey.generateIv());

        logger.info("IV used for encryption: " + new String(iv));
        System.out.println("File encrypted successfully: " + outputPath);

    }
    static void decryptFile() throws Exception{
        //Implementation will be here
        System.out.println("Enter the path of the encrypted file: ");
        String inputPath = in.nextLine().trim();
        System.out.println("Enter the path of the key file: ");
        String keyFile = in.nextLine().trim();

        //Load the key
        SecretKey secretKey = Decryption.loadKeyFromFile(keyFile);

        //Decrypt the file
        String outputPath = inputPath.replace(".enc",".dec");
        Decryption.decryptFile(inputPath, outputPath, secretKey);
        System.out.println("File decrypted successfully: " + outputPath);

    }
}