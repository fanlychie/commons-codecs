package org.fanlychie.commons.codecs.algorithm;

import org.fanlychie.commons.codecs.exception.RuntimeCastException;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 加密算法
 * Created by fanlychie on 2017/2/8.
 */
public final class RSA {

    /**
     * RSA 算法名称
     */
    private static final String RSA_ALGORITHM = "RSA";

    /**
     * 密钥长度 1024(117)
     */
    private static final int LENGTH = 1024;

    /**
     * 私有化
     */
    private RSA() {

    }

    /**
     * 生成密钥对
     *
     * @return 返回 RSA 公钥-私钥 密钥对
     */
    public static RSAKeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyGen.initialize(LENGTH);
            KeyPair pair = keyGen.generateKeyPair();
            return new RSAKeyPair(base64Encode(pair.getPublic().getEncoded()), base64Encode(pair.getPrivate().getEncoded()));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 私钥签名
     *
     * @param privateKey 私钥
     * @param ciphertext 密文内容
     * @return 返回私钥签名的字符串内容
     */
    public static String sign(String privateKey, String ciphertext) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(getRSAPrivateKey(privateKey));
            signature.update(ciphertext.getBytes());
            return base64Encode(signature.sign());
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 公钥验证签名
     *
     * @param publicKey  公钥
     * @param ciphertext 密文内容
     * @param signature  数字签名
     * @return 验证通过返回 true, 否则返回 false
     */
    public static boolean verify(String publicKey, String ciphertext, String signature) {
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initVerify(getRSAPublicKey(publicKey));
            sign.update(ciphertext.getBytes());
            return sign.verify(base64Decode(signature.getBytes()));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 公钥加密内容
     *
     * @param plaintext 明文内容
     * @param publicKey 公钥
     * @return 返回公钥加密的内容
     */
    public static String encryptByPublicKey(String plaintext, String publicKey) {
        try {
            return encrypt(plaintext, getRSAPublicKey(publicKey));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 私钥加密内容
     *
     * @param plaintext  明文内容
     * @param privateKey 私钥
     * @return 返回私钥加密的内容
     */
    public static String encryptByPrivateKey(String plaintext, String privateKey) {
        try {
            return encrypt(plaintext, getRSAPrivateKey(privateKey));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 公钥解密内容
     *
     * @param ciphertext 密文内容
     * @param publicKey  公钥
     * @return 返回公钥解密的内容
     */
    public static String decryptByPublicKey(String ciphertext, String publicKey) {
        try {
            return decrypt(ciphertext, getRSAPublicKey(publicKey));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 私钥解密内容
     *
     * @param ciphertext 密文内容
     * @param privateKey 私钥
     * @return 返回私钥解密的内容
     */
    public static String decryptByPrivateKey(String ciphertext, String privateKey) {
        try {
            return decrypt(ciphertext, getRSAPrivateKey(privateKey));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 获取 RSA 公钥对象
     *
     * @param publicKey 公钥字符串
     * @return 返回 RSA 公钥对象
     * @throws Throwable
     */
    private static RSAPublicKey getRSAPublicKey(String publicKey) throws Throwable {
        KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
        KeySpec keySpec = new X509EncodedKeySpec(getEncodedKeyBytes(publicKey));
        return (RSAPublicKey) factory.generatePublic(keySpec);
    }

    /**
     * 获取 RSA 私钥对象
     *
     * @param privateKey 私钥字符串
     * @return 返回 RSA 私钥对象
     * @throws Throwable
     */
    private static RSAPrivateKey getRSAPrivateKey(String privateKey) throws Throwable {
        KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
        KeySpec keySpec = new PKCS8EncodedKeySpec(getEncodedKeyBytes(privateKey));
        return (RSAPrivateKey) factory.generatePrivate(keySpec);
    }

    /**
     * 获取 Base64 编码的密钥字节数组
     *
     * @param key 密钥字符串
     * @return 返回 Base64 编码的密钥字节数组
     * @throws Throwable
     */
    private static byte[] getEncodedKeyBytes(String key) throws Throwable {
        key = key.replace("-----BEGIN PUBLIC KEY-----\n", "");
        key = key.replace("-----END PUBLIC KEY-----", "");
        return base64Decode(key.getBytes());
    }

    /**
     * RSA加密内容
     *
     * @param plaintext 明文内容
     * @param key       密钥
     * @return
     */
    private static String encrypt(String plaintext, Key key) throws Throwable {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return base64Encode(cipher.doFinal(plaintext.getBytes()));
    }

    /**
     * RSA解密内容
     *
     * @param ciphertext 密文内容
     * @param key        密钥
     * @return
     */
    private static String decrypt(String ciphertext, Key key) throws Throwable {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(base64Decode(ciphertext.getBytes())));
    }

    /**
     * Base64 编码字节数组
     *
     * @param sources 源字节数组
     * @return 返回编码后的字符串
     */
    private static String base64Encode(byte[] sources) throws Throwable {
        return new String(Base64.getEncoder().encode(sources));
    }

    /**
     * Base64 解码字节数组
     *
     * @param sources 源字节数组
     * @return 返回解码后的字节数组
     */
    private static byte[] base64Decode(byte[] sources) {
        return Base64.getDecoder().decode(sources);
    }

    /**
     * 公钥-私钥 密钥对
     */
    public static final class RSAKeyPair {

        /**
         * 公钥字符串
         */
        private String publicKey;

        /**
         * 私钥字符串
         */
        private String privateKey;

        /**
         * 创建密钥对对象
         *
         * @param publicKey  公钥字符串
         * @param privateKey 私钥字符串
         */
        private RSAKeyPair(String publicKey, String privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /**
         * 获取公钥
         *
         * @return 返回公钥字符串
         */
        public String getPublicKey() {
            return publicKey;
        }

        /**
         * 获取私钥
         *
         * @return 返回私钥字符串
         */
        public String getPrivateKey() {
            return privateKey;
        }

    }

}