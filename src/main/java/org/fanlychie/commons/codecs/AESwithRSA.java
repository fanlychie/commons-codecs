package org.fanlychie.commons.codecs;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * AES & RSA 加密
 * Created by fanlychie on 2017/2/10.
 */
public final class AESwithRSA {

    private static final byte[] SEED = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

    public static Cipher encryptByPublicKey(String plaintext, String publicKey) {
        return encryptByPublicKey(plaintext, publicKey, generateRandomSeed(16));
    }

    public static Cipher encryptByPrivateKey(String plaintext, String privateKey) {
        return encryptByPrivateKey(plaintext, privateKey, generateRandomSeed(16));
    }

    public static Cipher encryptByPublicKey(String plaintext, String publicKey, String secretKey) {
        return new Cipher(AES.encrypt(plaintext, secretKey), RSA.encryptByPublicKey(secretKey, publicKey));
    }

    public static Cipher encryptByPrivateKey(String plaintext, String privateKey, String secretKey) {
        return new Cipher(AES.encrypt(plaintext, secretKey), RSA.encryptByPrivateKey(secretKey, privateKey));
    }

    public static String decryptByPublicKey(String ciphertext, String publicKey, String secretKey) {
        return AES.decrypt(ciphertext, RSA.decryptByPublicKey(secretKey, publicKey));
    }

    public static String decryptByPrivateKey(String ciphertext, String privateKey, String secretKey) {
        return AES.decrypt(ciphertext, RSA.decryptByPrivateKey(secretKey, privateKey));
    }

    public static class Cipher {

        private String secretKey;

        private String cipherText;

        private Cipher(String cipherText, String secretKey) {
            this.cipherText = cipherText;
            this.secretKey = secretKey;
        }

        public String getCipherText() {
            return cipherText;
        }

        public String getSecretKey() {
            return secretKey;
        }

    }

    private static String generateRandomSeed(int size) {
        byte[] bytes = new byte[size];
        Random random = ThreadLocalRandom.current();
        for (int i = 0; i < size; i++) {
            bytes[i] = SEED[random.nextInt(SEED.length)];
        }
        return new String(bytes);
    }

}