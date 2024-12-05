//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.BitSet;
import java.security.SecureRandom;

class KeyGenerator {
    public static byte[] generate64BitKey(long seed) {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(seed);  // Set the seed
        byte[] key = new byte[8];    // 8 bytes = 64 bits
        secureRandom.nextBytes(key);
        return key;
    }

    public static byte[] generate128BitKey(long seed) {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(seed);   // Set the seed
        byte[] key = new byte[16];    // 16 bytes = 128 bits
        secureRandom.nextBytes(key);
        return key;
    }
}


public class Main {
    // Method to pad plaintext to a multiple of 16 bytes (PKCS7 padding)
    public static byte[] pad(byte[] plaintext, int pad_length) {
        int paddingRequired = pad_length - (plaintext.length % pad_length);
        byte[] padded = Arrays.copyOf(plaintext, plaintext.length + paddingRequired);
        Arrays.fill(padded, plaintext.length, padded.length, (byte) paddingRequired);
        return padded;
    }

    // Remove padding from decrypted text
    public static byte[] unpad(byte[] decrypted, int pad_length) {
        int paddingLength = decrypted[decrypted.length - 1] & 0xFF; // Get padding length
        if (paddingLength < 1 || paddingLength > pad_length) {
            throw new IllegalArgumentException("Invalid padding length: " + paddingLength);
        }
        return Arrays.copyOfRange(decrypted, 0, decrypted.length - paddingLength);
    }

    // Encrypt in blocks
    public static byte[] AESEncryptInBlocks(byte[] paddedPlaintext, byte[] key) {
        int blockSize = 16;
        int numBlocks = paddedPlaintext.length / blockSize; // Total number of blocks
        byte[] ciphertext = new byte[paddedPlaintext.length]; // Initialize ciphertext array

        for (int i = 0; i < numBlocks; i++) {
            int start = i * blockSize;
            byte[] block = Arrays.copyOfRange(paddedPlaintext, start, start + blockSize); // Get a block
            byte[] encryptedBlock = AES.encrypt(block, key); // Encrypt the block
            System.arraycopy(encryptedBlock, 0, ciphertext, start, blockSize); // Copy encrypted block
        }

        return ciphertext;
    }

    // Decrypt in blocks
    public static byte[] AESDecryptInBlocks(byte[] ciphertext, byte[] key) {
        int blockSize = 16;
        int numBlocks = ciphertext.length / blockSize; // Total number of blocks
        byte[] decryptedText = new byte[ciphertext.length]; // Initialize decrypted array

        for (int i = 0; i < numBlocks; i++) {
            int start = i * blockSize;
            byte[] block = Arrays.copyOfRange(ciphertext, start, start + blockSize); // Get a block
            byte[] decryptedBlock = AES.decrypt(block, key); // Decrypt the block
            System.arraycopy(decryptedBlock, 0, decryptedText, start, blockSize); // Copy decrypted block
        }

        return decryptedText;
    }

    public static byte[] AESEncryption(byte[] plaintext, byte[] key){
        byte[] paddedPlaintext = pad(plaintext, 16);
        return AESEncryptInBlocks(paddedPlaintext, key);
    }

    public static byte[] AESDecryption(byte[] ciphertext, byte[] key){
        // Decrypt the ciphertext in blocks
        byte[] decryptedText = AESDecryptInBlocks(ciphertext, key);

        // Remove padding from the decrypted text
        byte[] originalText = unpad(decryptedText, 16);
        return originalText;
    }

    // Encrypt in blocks
    public static byte[] DESEncryptInBlocks(byte[] paddedPlaintext, byte[] key) {
        int blockSize = 8;
        int numBlocks = paddedPlaintext.length / blockSize; // Total number of blocks
        byte[] ciphertext = new byte[paddedPlaintext.length]; // Initialize ciphertext array

        for (int i = 0; i < numBlocks; i++) {
            int start = i * blockSize;
            byte[] block = Arrays.copyOfRange(paddedPlaintext, start, start + blockSize); // Get a block
            byte[] encryptedBlock = DES.encrypt(block, key); // Encrypt the block
            System.arraycopy(encryptedBlock, 0, ciphertext, start, blockSize); // Copy encrypted block
        }

        return ciphertext;
    }

    // Decrypt in blocks
    public static byte[] DESDecryptInBlocks(byte[] ciphertext, byte[] key) {
        int blockSize = 8;
        int numBlocks = ciphertext.length / blockSize; // Total number of blocks
        byte[] decryptedText = new byte[ciphertext.length]; // Initialize decrypted array

        for (int i = 0; i < numBlocks; i++) {
            int start = i * blockSize;
            byte[] block = Arrays.copyOfRange(ciphertext, start, start + blockSize); // Get a block
            byte[] decryptedBlock = DES.decrypt(block, key); // Decrypt the block
            System.arraycopy(decryptedBlock, 0, decryptedText, start, blockSize); // Copy decrypted block
        }

        return decryptedText;
    }

    public static byte[] DESEncryption(byte[] plaintext, byte[] key){
        byte[] paddedPlaintext = pad(plaintext, 8);
        return DESEncryptInBlocks(paddedPlaintext, key);
    }

    public static byte[] DESDecryption(byte[] ciphertext, byte[] key){
        // Decrypt the ciphertext in blocks
        byte[] decryptedText = DESDecryptInBlocks(ciphertext, key);

        // Remove padding from the decrypted text
        byte[] originalText = unpad(decryptedText, 8);
        return originalText;
    }

//
//    public static void main(String[] args) {
//
//        long seed = 123456789L; // Your seed value
//
//        // Generate 64-bit key
//        byte[] key64 = KeyGenerator.generate64BitKey(seed);
//        System.out.println("Key64: " + byteArrayToHexString(key64));
//        // Generate 128-bit key
//        byte[] key128 = KeyGenerator.generate128BitKey(seed);
//        System.out.println("Key128: " + byteArrayToHexString(key128));
//
//        // Sample plaintext (16 bytes for AES)
//        String plaintextString = "Hello, RSA!";
//        byte[] plaintext = plaintextString.getBytes(); // Convert to byte array
//
//        byte[] AESCiphertext = AESEncryption(plaintext, key128);
//        System.out.println("AES cipher text: "+byteArrayToHexString(AESCiphertext));
//        byte[] AESDecryptionText = AESDecryption(AESCiphertext, key128);
//
//        byte[] DESCiphertext = DESEncryption(plaintext, key64);
//        System.out.println("DES cipher text: "+byteArrayToHexString(DESCiphertext));
//        byte[] DESDecryptionText = DESDecryption(DESCiphertext, key64);
//
//        byte[] md5 = MD5.md5(plaintext);
//        System.out.println("MD5: "+byteArrayToHexString(md5));
//
//        byte[] sha1 = SHA1.sha1(plaintext);
//        System.out.println("SHA1: "+byteArrayToHexString(sha1));
//
//        // 生成密钥对
//        RSA rsa = new RSA();
//
//        // 打印密钥对
//        System.out.println("公钥 (e, n): ");
//        System.out.println("e = " + rsa.getPublicKey());
//        System.out.println("n = " + rsa.getModulus());
//
//        System.out.println("\n私钥 (d, n): ");
//        System.out.println("d = " + rsa.getPrivateKey());
//        System.out.println("n = " + rsa.getModulus());
//    }

    // Helper function to convert byte array to hex string
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}