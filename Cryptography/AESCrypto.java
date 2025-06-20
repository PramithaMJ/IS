package Cryptography;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCrypto {
    public static void main(String[] args) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
         InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        byte[] keyArray = new byte[] {
                'T', 'h', 'i', 's', 'I', 's', 'A', 'K',
                'e', 'y', 'F', 'o', 'r', 'A', 'E', 'S'
        };

        SecretKeySpec secretKey = new SecretKeySpec(keyArray, "AES");

        System.out.println("Key as String: " + new String(secretKey.getEncoded()));
        byte[] keyBytes = secretKey.getEncoded();
        String keyString = new String(keyBytes);

        System.out.println("Key as Bytes: " + keyString);
        System.out.println("Secret key Size: " + keyString.length());

        Cipher aes;
        aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String ivString = "AAAAAAAAAAAAAAAA"; // IV must be 16 bytes for AES
        IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());

        aes.init(Cipher.ENCRYPT_MODE, secretKey, iv); // Initializing the cipher
        String msg = "I love pizza. You love pizza. Everyone loves pizza.";
        byte[] msgBytes = msg.getBytes();

        System.out.println("Plain Text: " + msg);
        // Encrypting the message
        byte[] encryptedBytes = aes.doFinal(msgBytes); // doFinal() method encrypts
        // the data and returns the encrypted bytes.
        // Display encrypted text as Base64 instead of raw bytes
        System.out.println("Encrypted Text: " + java.util.Base64.getEncoder().encodeToString(encryptedBytes));
        // Decrypting the message - MUST provide the SAME IV
        aes.init(Cipher.DECRYPT_MODE, secretKey, iv); // Added the IV parameter
        byte[] decryptedBytes = aes.doFinal(encryptedBytes);
        String decryptedMsg = new String(decryptedBytes);
        System.out.println("Decrypted Text: " + decryptedMsg);
        System.out.println("Decryption successful: " + msg.equals(decryptedMsg));
        System.out.println("AES Algorithm: " + secretKey.getAlgorithm());
        System.out.println("AES Key Size: " + secretKey.getEncoded().length * 8 + " bits");
        System.out.println("AES Key Format: " + secretKey.getFormat());
        System.out.println("AES Key Encoded: " + java.util.Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    }    
}
