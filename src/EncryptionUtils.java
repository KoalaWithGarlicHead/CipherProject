import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;

public class EncryptionUtils {

    // Helper function to convert byte array to hex string
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    // 将十六进制字符串转换为字节数组
    public static byte[] hexStringToByteArray(String hex) {
        int length = hex.length();
        byte[] data = new byte[length / 2]; // 每两个十六进制字符对应一个字节
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // 获取输入数据（字符串或文件）
    public static byte[] getInputData(String inputType, String inputString, File inputFile) throws IOException {
        if (inputType.equals("String")) {
            return inputString.getBytes(); // 字符串转为字节数组
        } else if (inputType.equals("File")) {
            return Files.readAllBytes(inputFile.toPath()); // 读取文件内容为字节数组
        }
        return null;
    }

    // 加密数据
    public static byte[] encrypt(String algorithm, byte[] data, byte[] key) {
        if (algorithm.equals("AES")) {
            return Main.AESEncryption(data, key);
        } else if (algorithm.equals("DES")) {
            return Main.DESEncryption(data, key);
        }
        return null;
    }

    // 解密数据
    public static byte[] decrypt(String algorithm, byte[] data, byte[] key) {
        if (algorithm.equals("AES")) {
            return Main.AESDecryption(data, key);
        } else if (algorithm.equals("DES")) {
            return Main.DESDecryption(data, key);
        }
        return null;
    }

    // 签名数据
    public static BigInteger sign(byte[] hash, RSA rsa) {
        BigInteger hashBigInt = new BigInteger(1, hash); // 1 表示正数
        BigInteger hashEncrypted = rsa.encrypt(hashBigInt); // 用私钥加密哈希值
        System.out.println(hashEncrypted);
        return hashEncrypted;

    }

    // 获取公私钥
    public static BigInteger getPublicKey(RSA rsa){
        return rsa.getPublicKey();
    }

    public static BigInteger getPrivateKey(RSA rsa){
        return rsa.getPrivateKey();
    }

    // 验证签名
    public static boolean verifySignature(BigInteger signature, byte[] deprecatedText, RSA rsa, BigInteger publicKey, BigInteger modulus, String hashAlgorithm) {
        rsa.SetPublicKey(publicKey);
        rsa.SetModulus(modulus);
        BigInteger decryptedHash = rsa.decrypt(signature);
        byte[] recalculatedHash = hashAlgorithm.equals("MD5") ? MD5.md5(deprecatedText) : SHA1.sha1(deprecatedText);
        BigInteger recalculatedHashBigInt = new BigInteger(1, recalculatedHash); // 1 表示正数
        return decryptedHash.equals(recalculatedHashBigInt); // 对比解密结果和重新计算的哈希值
    }
}
