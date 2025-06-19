import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Key size can be 1024, 2048
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);

        String message = "I love pizza. You love pizza. Everyone loves pizza.";
        System.out.println("\nOriginal Message: " + message);

        // Encryption
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] byteMsg = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encryptCipher.doFinal(byteMsg);
        String encodedEncryptedMsg = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("\nEncrypted Message: " + encodedEncryptedMsg);
        
        // Decryption
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("\nDecrypted Message: " + decryptedMessage);

        // Check if decryption was successful
        if (message.equals(decryptedMessage)) {
            System.out.println("\nDecryption successful: The decrypted message matches the original.");
        } else {
            System.out.println("\nDecryption failed: The decrypted message does not match the original.");
        }
        System.out.println("RSA Algorithm: " + publicKey.getAlgorithm());
        System.out.println("Public Key Format: " + publicKey.getFormat());
        System.out.println("Private Key Format: " + privateKey.getFormat());
    }
}
