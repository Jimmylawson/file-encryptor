import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class for generating cryptographic keys and parameters for AES-GCM encryption.
 */
public class GenerateSecretKey {

    /**
     * Generates a KeyGenerator instance for AES encryption with the specified key size.
     * 
     * @param n The key size in bits (128, 192, or 256 for AES)
     * @return initialized KeyGenerator instance
     * @throws NoSuchAlgorithmException if the AES algorithm is not available
     */
    public SecretKey generateKeyGenerator(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    /**
     * Generates a random Initialization Vector (IV) for use in AES-GCM encryption.
     * IV is used as a nonce (number used once) in GCM mode.
     * @return GCMParameterSpec containing a 12-byte random IV and 128-bit authentication tag length
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     * @throws NoSuchPaddingException if the specified padding scheme is not available
     * 
     * The IV (Nonce) in GCM mode must be unique for each encryption operation with the same key.
     * GCM provides both confidentiality and authentication (AEAD - Authenticated Encryption
     * with Associated Data).
     * 
     * Note on GCM parameters:
     * - 12-byte IV is recommended for GCM (more efficient and secure)
     * - 128-bit authentication tag provides strong integrity protection
     * - The IV doesn't need to be secret but must be unique for each encryption
     * - The IV must be stored/transmitted with the ciphertext for decryption
     */
    public static GCMParameterSpec generateIv() throws NoSuchAlgorithmException, NoSuchPaddingException {
        // Verify GCM is available
        Cipher.getInstance("AES/GCM/NoPadding");
        
        // Generate a 12-byte IV (recommended for GCM)
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        // 128-bit authentication tag length (in bits)
        return new GCMParameterSpec(128, iv);
    }
}
