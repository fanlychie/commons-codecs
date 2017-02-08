package org.fanlychie.commons.codecs.algorithm;

import org.fanlychie.commons.codecs.exception.RuntimeCastException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES 对称加密算法
 * Created by fanlychie on 2017/2/8.
 */
public final class AES {

    /**
     * AES 算法名称
     */
    private static final String AES_ALGORITHM = "AES";

    /**
     * 密钥长度 128(16)/192(24)/256(32)
     */
    private static final int LENGTH = 128;

    /**
     * UTF-8 字符集编码
     */
    private static final String CHARSET_UTF_8 = "UTF-8";

    /**
     * 私有化
     */
    private AES() {

    }

    /**
     * 加密内容
     *
     * @param plaintext 明文内容
     * @param key       加密所使用的密钥串
     * @return
     */
    public static String encrypt(String plaintext, String key) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(AES_ALGORITHM);
            generator.init(LENGTH, new SecureRandom(key.getBytes()));
            SecretKeySpec spec = new SecretKeySpec(generator.generateKey().getEncoded(), AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, spec);
            byte[] bytes = cipher.doFinal(plaintext.getBytes(CHARSET_UTF_8));
            return new String(Base64.getEncoder().encode(bytes));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    /**
     * 解密内容
     *
     * @param ciphertext 密文内容
     * @param key        加密所使用的密钥串
     * @return
     */
    public static String decrypt(String ciphertext, String key) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(AES_ALGORITHM);
            generator.init(LENGTH, new SecureRandom(key.getBytes()));
            SecretKeySpec spec = new SecretKeySpec(generator.generateKey().getEncoded(), AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, spec);
            byte[] bytes = Base64.getDecoder().decode(ciphertext.getBytes(CHARSET_UTF_8));
            return new String(cipher.doFinal(bytes));
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

}