package Cryptography;
import javax.crypto.Cipher;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import java.util.Base64;

public class DESBruteForce {
    public static void main(String[] args) throws Exception {
        // Known values from the target system
        String knownPlaintext = "I love pizza. You love pizza. Everyone loves pizza.";

        // Replace this with the actual Base64-encoded output from your Crypto.java
        String knownCiphertext = "wM9cvIXUFYZqKRdKMwenyMd1PJeAQxkuUtK4Yxf9cnrmCSQlBPSZhIDqj2CM3adgbRcdfXZveNA=";
        byte[] knownCiphertextBytes = Base64.getDecoder().decode(knownCiphertext);

        // Known IV (from the insecure code, it's "AAAAAAAA")
        String ivString = "AAAAAAAA";
        IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());

        System.out.println("Starting brute force attack...");
        System.out.println("This may take a while for demonstration purposes.");

        // Brute force constraints - in practice, using a smaller range for
        // demonstration
        long startKey = 0;
        long endKey = 1000000; // Much smaller than 2^56 for demo purposes
        long count = 0;

        for (long i = startKey; i <= endKey; i++) {
            try {
                // Convert current number to 8-byte key
                byte[] keyBytes = new byte[8];
                for (int j = 0; j < 8; j++) {
                    keyBytes[7 - j] = (byte) ((i >> (j * 8)) & 0xFF);
                }

                // Try this key
                DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
                SecretKey secretKey = SecretKeyFactory.getInstance("DES").generateSecret(desKeySpec);

                // Attempt decryption
                Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
                des.init(Cipher.DECRYPT_MODE, secretKey, iv);
                byte[] decryptedBytes = des.doFinal(knownCiphertextBytes);
                String decryptedText = new String(decryptedBytes);

                // Print progress occasionally
                if (++count % 10000 == 0) {
                    System.out.println("Tried " + count + " keys...");
                }

                // Check if we found the right key
                if (decryptedText.equals(knownPlaintext)) {
                    System.out.println("Found key: " + bytesToHex(keyBytes));
                    System.out.println("Original text successfully decrypted!");
                    break;
                }
            } catch (Exception e) {
                // Invalid keys may cause exceptions - just continue
            }
        }
        System.out.println("Brute force attempt completed.");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}