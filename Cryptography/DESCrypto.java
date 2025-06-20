package Cryptography;
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
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DESCrypto {
    public static void main(String[] args)
            throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String key = "12345678";
        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes());
        SecretKey secretKey = SecretKeyFactory.getInstance("DES").generateSecret(desKeySpec);
        // KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        // SecretKey secretKey = keyGen.generateKey();
        // System.out.println("Generated Secret Key: " + secretKey);

        byte[] keyBytes = secretKey.getEncoded();
        String keyString = new String(keyBytes);
        System.out.println("Key as String: " + keyString);
        System.out.println("Secret key Size: " + keyString.length());
        System.out.println("Secret key Algorithm: " + secretKey.getAlgorithm());

        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding"); // ECB mode have vulnerabilities, patterns can be detected in the encrypted data.
        // We use padding to ensure that the plaintext is a multiple of the block size
        // and to handle any remaining bytes that do not fit into a complete block.

        // Initializing a vector (IV) for DES encryption.
        String ivString = "AAAAAAAA"; // IV must be 8 bytes for DES
        IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());

        des.init(Cipher.ENCRYPT_MODE, secretKey, iv); // Initializing the cipher

        String msg = "I love pizza. You love pizza. Everyone loves pizza.";
        byte[] msgBytes = msg.getBytes();
        System.out.println("Plain Text: " + msg);

        // Encrypting the message
        byte[] encryptedBytes = des.doFinal(msgBytes); // doFinal() method encrypts the data and returns the encrypted bytes.
        // Display encrypted text as Base64 instead of raw bytes
        System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(encryptedBytes));

        // Decrypting the message - MUST provide the SAME IV
        des.init(Cipher.DECRYPT_MODE, secretKey, iv); // Added the IV parameter here
        byte[] decryptedBytes = des.doFinal(encryptedBytes);
        String decryptedMsg = new String(decryptedBytes);
        System.out.println("Decrypted Text: " + decryptedMsg);
    }
}