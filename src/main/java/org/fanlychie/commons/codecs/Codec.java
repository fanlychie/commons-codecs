package org.fanlychie.commons.codecs;

import org.fanlychie.commons.codecs.algorithm.AES;
import org.fanlychie.commons.codecs.algorithm.MD5;

/**
 * 编码解码器
 * Created by fanlychie on 2017/2/8.
 */
public final class Codec {

    /**
     * 私有化
     */
    private Codec() {

    }

    public static String md5Encrypt(String content) {
        return MD5.encrypt(content);
    }

    public static String aesEncrypt(String plaintext, String key) {
        return AES.encrypt(plaintext, key);
    }

    public static String aesDecrypt(String ciphertext, String key) {
        return AES.decrypt(ciphertext, key);
    }

}