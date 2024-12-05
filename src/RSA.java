import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class RSA {

    private static final SecureRandom random = new SecureRandom();
    private static final int BIT_LENGTH = 200; // 密钥长度，至少 200 位

    // 密钥对
    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger modulus;

    // 构造函数，生成密钥对
    public RSA() {
        // 1. 生成两个大素数 p 和 q
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH / 2, random);
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH / 2, random);

        // 2. 计算 n 和 φ(n)
        modulus = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // 3. 选择公钥 e
        publicKey = BigInteger.valueOf(65537); // 通常选择 65537
        if (!phi.gcd(publicKey).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("公钥 e 与 φ(n) 必须互质");
        }

        // 4. 计算私钥 d
        privateKey = publicKey.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        BigInteger encryptedInt = message.modPow(privateKey, modulus); // 执行加密操作
        return encryptedInt;
    }

    public BigInteger decrypt(BigInteger ciphertext) {
        BigInteger decryptedInt = ciphertext.modPow(publicKey, modulus); // 执行解密操作
        return decryptedInt;
    }

    // 获取公钥
    public BigInteger getPublicKey() {
        return publicKey;
    }

    // 获取私钥
    public BigInteger getPrivateKey() {
        return privateKey;
    }

    // 获取模数 n
    public BigInteger getModulus() {
        return modulus;
    }

    public void SetPrivateKey(BigInteger key){
        privateKey = key;
    }

    public void SetPublicKey(BigInteger key){
        publicKey = key;
    }

    public void SetModulus(BigInteger key){
        modulus = key;
    }
}

