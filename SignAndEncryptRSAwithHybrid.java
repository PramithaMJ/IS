import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SignAndEncryptRSAwithHybrid {
        public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidAlgorithmParameterException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Key size can be 1024, 2048
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);

        String message = "I love pizza. You love pizza. Everyone loves pizza.";
        System.out.println("\nOriginal Message: " + message);

        // Digital Signature - Signing
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        String encodedSignature = Base64.getEncoder().encodeToString(signatureBytes);
        System.out.println("\nDigital Signature: " + encodedSignature);

        // Digital Signature - Verification
        Signature verifySignature = Signature.getInstance("SHA256withRSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(message.getBytes(StandardCharsets.UTF_8));
        boolean signatureValid = verifySignature.verify(signatureBytes);
        System.out.println("\nSignature Verification: " + (signatureValid ? "Valid" : "Invalid"));

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
        
        // Demonstrate sign-then-encrypt using a hybrid approach (RSA for signing, AES-GCM for encryption)
        System.out.println("\n--- Sign-then-Encrypt Process (Hybrid Approach) ---");
        
        // First sign the message with RSA
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = sig.sign();
        
        // Combine message and signature
        String signedMessage = message + ":::" + Base64.getEncoder().encodeToString(signBytes);
        System.out.println("Signed Message (before encryption): " + signedMessage);
        
        // Generate a symmetric key for AES encryption
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        
        // Generate a random IV (Initialization Vector) for AES-GCM
        byte[] iv = new byte[12]; // 12 bytes IV for GCM
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
        
        // Encrypt the signed message with AES-GCM
        Cipher encryptSignedCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptSignedCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedSignedBytes = encryptSignedCipher.doFinal(signedMessage.getBytes(StandardCharsets.UTF_8));
        
        // Encrypt the AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        
        // Combine everything into a single message
        String encryptedPackage = Base64.getEncoder().encodeToString(encryptedAesKey) + ":::" +
                                 Base64.getEncoder().encodeToString(iv) + ":::" +
                                 Base64.getEncoder().encodeToString(encryptedSignedBytes);
        System.out.println("Encrypted Package: " + encryptedPackage);
        
        // Decrypt process
        // Split the package
        String[] packageParts = encryptedPackage.split(":::");
        byte[] encryptedKey = Base64.getDecoder().decode(packageParts[0]);
        byte[] receivedIv = Base64.getDecoder().decode(packageParts[1]);
        byte[] encryptedData = Base64.getDecoder().decode(packageParts[2]);
        
        // Decrypt the AES key using RSA private key
        Cipher rsaDecryptCipher = Cipher.getInstance("RSA");
        rsaDecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = rsaDecryptCipher.doFinal(encryptedKey);
        SecretKey decryptedAesKey = new SecretKeySpec(decryptedKeyBytes, "AES");
        
        // Decrypt the data using the decrypted AES key
        GCMParameterSpec decryptGcmSpec = new GCMParameterSpec(128, receivedIv);
        Cipher decryptSignedCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decryptSignedCipher.init(Cipher.DECRYPT_MODE, decryptedAesKey, decryptGcmSpec);
        byte[] decryptedSignedBytes = decryptSignedCipher.doFinal(encryptedData);
        String decryptedSignedMessage = new String(decryptedSignedBytes, StandardCharsets.UTF_8);
        System.out.println("Decrypted Signed Message: " + decryptedSignedMessage);
        
        // Split message and signature
        String[] parts = decryptedSignedMessage.split(":::");
        String retrievedMessage = parts[0];
        byte[] retrievedSignatureBytes = Base64.getDecoder().decode(parts[1]);
        
        // Verify signature
        Signature verifyFinalSignature = Signature.getInstance("SHA256withRSA");
        verifyFinalSignature.initVerify(publicKey);
        verifyFinalSignature.update(retrievedMessage.getBytes(StandardCharsets.UTF_8));
        boolean finalVerification = verifyFinalSignature.verify(retrievedSignatureBytes);
        System.out.println("Final Signature Verification: " + (finalVerification ? "Valid" : "Invalid"));
        
        System.out.println("\nRSA Algorithm: " + publicKey.getAlgorithm());
        System.out.println("Public Key Format: " + publicKey.getFormat());
        System.out.println("Private Key Format: " + privateKey.getFormat());
    }
}
