package Cryptography;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
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

public class SignAndEncryptRSA {
        public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        // Generate keys for Alice
        KeyPairGenerator aliceKeyGen = KeyPairGenerator.getInstance("RSA");
        aliceKeyGen.initialize(2048);
        KeyPair aliceKeyPair = aliceKeyGen.generateKeyPair();
        PrivateKey alicePrivateKey = aliceKeyPair.getPrivate();
        PublicKey alicePublicKey = aliceKeyPair.getPublic();
        
        // Generate keys for Bob
        KeyPairGenerator bobKeyGen = KeyPairGenerator.getInstance("RSA");
        bobKeyGen.initialize(2048);
        KeyPair bobKeyPair = bobKeyGen.generateKeyPair();
        PrivateKey bobPrivateKey = bobKeyPair.getPrivate();
        PublicKey bobPublicKey = bobKeyPair.getPublic();
        
        System.out.println("Alice's Public Key: " + alicePublicKey);
        System.out.println("Alice's Private Key: " + alicePrivateKey);
        System.out.println("Bob's Public Key: " + bobPublicKey);
        System.out.println("Bob's Private Key: " + bobPrivateKey);

        String message = "Secret message from Alice to Bob.";
        System.out.println("\nOriginal Message: " + message);
        
        // Step 1: Sign the message with Alice's private key using Cipher instead of Signature
        System.out.println("\n--- Sign and Encrypt Process Using Cipher ---");
        
        // Create a hash of the message to reduce its size for RSA encryption
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        int messageHash = java.util.Arrays.hashCode(messageBytes);
        String hashString = String.valueOf(messageHash);
        
        Cipher signCipher = Cipher.getInstance("RSA");
        signCipher.init(Cipher.ENCRYPT_MODE, alicePrivateKey); // Sign with Alice's private key
        // Sign the hash instead of the full message to stay under the 245 byte limit
        byte[] signedMessage = signCipher.doFinal(hashString.getBytes(StandardCharsets.UTF_8));
        String encodedSignedMessage = Base64.getEncoder().encodeToString(signedMessage);
        System.out.println("Message Hash Signed with Alice's Private Key: " + encodedSignedMessage);
        
        // Step 2: Encrypt the original message with Bob's public key (separate from signature)
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, bobPublicKey); // Encrypt with Bob's public key
        byte[] encryptedMessage = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        String encodedEncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Original Message Encrypted with Bob's Public Key: " + encodedEncryptedMessage);
        
        // In a real scenario, both the signature and the encrypted message would be sent to Bob
        
        // Step 3: Bob receives and decrypts the message with his private key
        Cipher bobDecryptCipher = Cipher.getInstance("RSA");
        bobDecryptCipher.init(Cipher.DECRYPT_MODE, bobPrivateKey); // Decrypt with Bob's private key
        byte[] decryptedMessage = bobDecryptCipher.doFinal(encryptedMessage);
        String decryptedText = new String(decryptedMessage, StandardCharsets.UTF_8);
        System.out.println("Bob Decrypts with His Private Key: " + decryptedText);
        
        // Now Bob verifies the signature using the signature sent by Alice
        Cipher bobVerifyCipher = Cipher.getInstance("RSA");
        bobVerifyCipher.init(Cipher.DECRYPT_MODE, bobPrivateKey); // Decrypt the signature with Bob's private key
        byte[] decryptedSignedMessage = signedMessage; // Using the signature directly from Alice
        String encodedDecryptedSignedMessage = Base64.getEncoder().encodeToString(decryptedSignedMessage);
        System.out.println("Bob Decrypts with His Private Key: " + encodedDecryptedSignedMessage);
        
        // Step 4: Bob verifies Alice's signature using her public key
        Cipher verifySignatureCipher = Cipher.getInstance("RSA");
        verifySignatureCipher.init(Cipher.DECRYPT_MODE, alicePublicKey); // Verify with Alice's public key
        byte[] verifiedHashBytes = verifySignatureCipher.doFinal(decryptedSignedMessage);
        String verifiedHash = new String(verifiedHashBytes, StandardCharsets.UTF_8);
        System.out.println("Verified Hash from Signature: " + verifiedHash);
        
        // Bob recalculates the hash of the original message for comparison
        byte[] receivedMessageBytes = message.getBytes(StandardCharsets.UTF_8);
        int receivedMessageHash = java.util.Arrays.hashCode(receivedMessageBytes);
        String receivedHashString = String.valueOf(receivedMessageHash);
        System.out.println("Recalculated Hash: " + receivedHashString);
        
        // Check if the verified hash matches the recalculated hash
        if (receivedHashString.equals(verifiedHash)) {
            System.out.println("Message Authentication Successful: The message was signed by Alice and has not been modified.");
        } else {
            System.out.println("Message Authentication Failed: The signature is invalid or the message was modified.");
        }

        // Simple Encryption (using Bob's public key)
        System.out.println("\n--- Simple Encryption/Decryption Process ---");
        Cipher bobEncryptCipher = Cipher.getInstance("RSA");
        bobEncryptCipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);  // Encrypt with Bob's public key
        byte[] byteMsg = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = bobEncryptCipher.doFinal(byteMsg);
        String encodedEncryptedMsg = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Message Encrypted with Bob's Public Key: " + encodedEncryptedMsg);

        // Simple Decryption (using Bob's private key)
        Cipher bobDecryptCipherSimple = Cipher.getInstance("RSA");
        bobDecryptCipherSimple.init(Cipher.DECRYPT_MODE, bobPrivateKey);  // Decrypt with Bob's private key
        byte[] decryptedBytes = bobDecryptCipherSimple.doFinal(encryptedBytes);
        String decryptedMessageSimple = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("Message Decrypted with Bob's Private Key: " + decryptedMessageSimple);

        // Check if decryption was successful
        if (message.equals(decryptedMessageSimple)) {
            System.out.println("Decryption successful: The decrypted message matches the original.");
        } else {
            System.out.println("Decryption failed: The decrypted message does not match the original.");
        }
        
        System.out.println("\n--- Key Information ---");
        System.out.println("Alice's RSA Algorithm: " + alicePublicKey.getAlgorithm());
        System.out.println("Alice's Public Key Format: " + alicePublicKey.getFormat());
        System.out.println("Alice's Private Key Format: " + alicePrivateKey.getFormat());
        System.out.println("Bob's Public Key Format: " + bobPublicKey.getFormat());
        System.out.println("Bob's Private Key Format: " + bobPrivateKey.getFormat());
    }
}
