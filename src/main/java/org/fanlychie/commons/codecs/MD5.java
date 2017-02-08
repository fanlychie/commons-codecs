package org.fanlychie.commons.codecs;

import org.fanlychie.commons.codecs.exception.RuntimeCastException;

import java.security.MessageDigest;

/**
 * MD5 信息摘要
 * Created by fanlychie on 2017/2/8.
 */
public final class MD5 {

    /**
     * MD5 算法名称
     */
    private static final String MD5_ALGORITHM = "MD5";

    /**
     * 哈希字符数组
     */
    private static final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * 私有化
     */
    private MD5() {

    }

    /**
     * MD5 信息摘要
     *
     * @param content 文本内容
     * @return 返回摘要信息
     */
    public static String encrypt(String content) {
        try {
            MessageDigest md5 = MessageDigest.getInstance(MD5_ALGORITHM);
            byte[] bytes = md5.digest(content.getBytes());
            char[] hexDigest = encodeHex(bytes);
            return new String(hexDigest);
        } catch (Throwable e) {
            throw new RuntimeCastException(e);
        }
    }

    private static char[] encodeHex(byte[] bytes) {
        char chars[] = new char[32];
        for (int i = 0; i < chars.length; i = i + 2) {
            byte b = bytes[i / 2];
            chars[i] = HEX_CHARS[(b >>> 0x4) & 0xf];
            chars[i + 1] = HEX_CHARS[b & 0xf];
        }
        return chars;
    }

}