import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DESede {
    public static void main(String[] args) 
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
               InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
               InvalidKeySpecException {

        // Triple DES requires a 24-byte key (3 DES keys combined)
        String keyStr = "123456781234567812345678"; // 24 characters for 3DES
        byte[] keyBytes = keyStr.getBytes();
        
        // Create Triple DES key specification
        DESedeKeySpec desedeKeySpec = new DESedeKeySpec(keyBytes);
        SecretKey secretKey = SecretKeyFactory.getInstance("DESede").generateSecret(desedeKeySpec);
        
        // Print key information
        String keyString = new String(secretKey.getEncoded());
        System.out.println("Key as String: " + keyString);
        System.out.println("Secret key Size: " + secretKey.getEncoded().length + " bytes");
        System.out.println("Secret key Algorithm: " + secretKey.getAlgorithm());

        // Use DESede (Triple DES) cipher instead of regular DES
        Cipher desede = Cipher.getInstance("DESede/CBC/PKCS5Padding"); // ECB mode have vulnerabilities, patterns can be detected in the encrypted data.
        // We use padding to ensure that the plaintext is a multiple of the block size
        // and to handle any remaining bytes that do not fit into a complete block.

        // Initializing a vector (IV) for Triple DES encryption.
        String ivString = "AAAAAAAA"; // IV must be 8 bytes for Triple DES as well
        IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());

        desede.init(Cipher.ENCRYPT_MODE, secretKey, iv); // Initializing the cipher

        String msg = "I love pizza. You love pizza. Everyone loves pizza.";
        byte[] msgBytes = msg.getBytes();
        System.out.println("Plain Text: " + msg);

        // Encrypting the message
        byte[] encryptedBytes = desede.doFinal(msgBytes); // doFinal() method encrypts the data and returns the encrypted bytes.
        // Display encrypted text as Base64 instead of raw bytes
        System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(encryptedBytes));

        // Decrypting the message - MUST provide the SAME IV
        desede.init(Cipher.DECRYPT_MODE, secretKey, iv); // Added the IV parameter here
        byte[] decryptedBytes = desede.doFinal(encryptedBytes);
        String decryptedMsg = new String(decryptedBytes);
        System.out.println("Decrypted Text: " + decryptedMsg);
    }
}
