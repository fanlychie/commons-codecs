package org.fanlychie.commons.codecs;

import org.fanlychie.commons.codecs.exception.RuntimeCastException;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
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
     * UTF-8 字符集编码
     */
    private static final String CHARSET_UTF_8 = "UTF-8";

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
     * @return
     */
    public static String sign(PrivateKey privateKey, String ciphertext) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey.source);
            signature.update(ciphertext.getBytes(CHARSET_UTF_8));
            return base64Encode(signature.sign());
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 公钥验证签名
     *
     * @param publicKey  公钥
     * @param ciphertext 密文内容
     * @param signature  数字签名
     * @return
     */
    public static boolean verify(PublicKey publicKey, String ciphertext, String signature) {
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initVerify(publicKey.source);
            sign.update(ciphertext.getBytes(CHARSET_UTF_8));
            return sign.verify(base64Decode(signature.getBytes(CHARSET_UTF_8)));
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 公钥加密内容
     *
     * @param plaintext 明文内容
     * @param publicKey 公钥
     * @return
     */
    public static String encrypt(String plaintext, PublicKey publicKey) {
        return encrypt(plaintext, publicKey.source);
    }

    /**
     * 私钥加密内容
     *
     * @param plaintext  明文内容
     * @param privateKey 私钥
     * @return
     */
    public static String encrypt(String plaintext, PrivateKey privateKey) {
        return encrypt(plaintext, privateKey.source);
    }

    /**
     * 公钥解密内容
     *
     * @param ciphertext 密文内容
     * @param publicKey  公钥
     * @return
     */
    public static String decrypt(String ciphertext, PublicKey publicKey) {
        return decrypt(ciphertext, publicKey.source);
    }

    /**
     * 私钥解密内容
     *
     * @param ciphertext 密文内容
     * @param privateKey 私钥
     * @return
     */
    public static String decrypt(String ciphertext, PrivateKey privateKey) {
        return decrypt(ciphertext, privateKey.source);
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

    private static RSAPublicKey getRSAPublicKey(String publicKey) throws Throwable {
        KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
        KeySpec keySpec = new X509EncodedKeySpec(getEncodedKeyBytes(publicKey));
        return (RSAPublicKey) factory.generatePublic(keySpec);
    }

    private static RSAPrivateKey getRSAPrivateKey(String privateKey) throws Throwable {
        KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
        KeySpec keySpec = new PKCS8EncodedKeySpec(getEncodedKeyBytes(privateKey));
        return (RSAPrivateKey) factory.generatePrivate(keySpec);
    }

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
    private static String encrypt(String plaintext, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return base64Encode(cipher.doFinal(plaintext.getBytes(CHARSET_UTF_8)));
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * RSA解密内容
     *
     * @param ciphertext 密文内容
     * @param key        密钥
     * @return
     */
    private static String decrypt(String ciphertext, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(base64Decode(ciphertext)), CHARSET_UTF_8);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Base64 编码字节数组
     *
     * @param src 源字节数组
     * @return 返回编码后的字符串
     */
    private static String base64Encode(byte[] src) throws Throwable {
        return new String(Base64.getEncoder().encode(src), CHARSET_UTF_8);
    }

    /**
     * Java 1.8 开始提供 java.util.Base64, 低于 Java 1.8 的可使用 Apache 的 Base64 算法替换：
     * <p>
     * org.apache.commons.codec.binary.Base64.decodeBase64(byte[] src)
     *
     * @param src 源字节数组
     * @return
     */
    private static byte[] base64Decode(byte[] src) {
        return Base64.getDecoder().decode(src);
    }

}