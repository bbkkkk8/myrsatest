package com.smartmining.test.encrypt;

import com.alibaba.fastjson.JSON;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class RSAUtils2 {
    // 初始化密钥对生成器，密钥大小为512-1024位
    private static int keysize = 512;
    private static String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAI7uJMUhS7yE9W/ueaOhaNKOJcPcnrCvoUOcZxvdlssHUtelLWGgVjDELHYs+6gdNXrv54/l31RZW5kpI7FMdD0CAwEAAQ==";
    private static String privateKey = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAju4kxSFLvIT1b+55o6Fo0o4lw9yesK+hQ5xnG92WywdS16UtYaBWMMQsdiz7qB01eu/nj+XfVFlbmSkjsUx0PQIDAQABAkAk5qbnnikHiuwy8cbF0C5X7gsh/huaUj24TvDv6M29rMneHPp7IuNkFcH6OoFNU8PeCTIyj5ZLsb7rX2n6KCkBAiEA5phtF4UGOdq3fmlsR7zBiGcSXbkw6dTahYu9jn0kd5kCIQCerUMXT/47s3mlNs6RquNYFIPYGEidc8EBbawjKPz4RQIhALfNW3dZ0uKekZAzW9m6fNDKx3rpODHKNfworIk8+qpRAiAIKgoFrQv7rmRX59YBELXZ1lRiTf2OfGI13Jq6xGUfsQIgEPH6yvM+5p/Cz6eXL70wVkjsjZn5nW95vn/GnUHfru8=";
    private static RSAPublicKey publicKeyCache;
    private static RSAPrivateKey privateKeyCache;
    private static Cipher cipherPrivateKeyCahe;
    private static Cipher cipherPublicKeyCahe;
    static {
        try {
            publicKeyCache = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
            cipherPublicKeyCahe    = Cipher.getInstance("RSA");
            cipherPublicKeyCahe.init(Cipher.ENCRYPT_MODE, publicKeyCache);
            privateKeyCache = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
            cipherPrivateKeyCahe= Cipher.getInstance("RSA");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    //随机生成密钥对
    public static void genKeyPair() {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = null;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // 初始化密钥对生成器，密钥大小为512-1024位
        assert keyPairGen != null;
        keyPairGen.initialize(keysize, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥
        // 得到公钥字符串
        String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        System.err.println(publicKeyString);
        // 得到私钥字符串
        String privateKeyString = new String(Base64.getEncoder().encode((privateKey.getEncoded())));
        System.err.println(privateKeyString);

    }

    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     */
    public static String encrypt(String str, String publicKey) {
        //base64编码的公钥
        byte[] decoded = Base64.getDecoder().decode(publicKey);
        RSAPublicKey pubKey;
        String outStr = null;

        try {
            pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            outStr = Base64.getEncoder().encodeToString((cipher.doFinal(str.getBytes(StandardCharsets.UTF_8))));
        } catch (Exception e) {
            e.printStackTrace();
        }
        //RSA加密
        return outStr;
    }

    public static String encrypt(String str) {
        //base64编码的公钥
        String outStr = null;
        try {
            outStr = Base64.getEncoder().encodeToString((cipherPublicKeyCahe.doFinal(str.getBytes(StandardCharsets.UTF_8))));
        } catch (Exception e) {
            e.printStackTrace();
        }
        //RSA加密
        return outStr;
    }

    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 铭文
     */
    public static String decrypt(String str, String privateKey) {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));
        //base64编码的私钥
        byte[] decoded = Base64.getDecoder().decode(privateKey);
        RSAPrivateKey priKey = null;
        //RSA解密
        Cipher cipher;
        String outStr = null;
        try {
            priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            outStr = new String(cipher.doFinal(inputByte));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return outStr;
    }

    public static String decrypt(String str) {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));
        String outStr = null;
        try {
            cipherPrivateKeyCahe.init(Cipher.DECRYPT_MODE, privateKeyCache);
            outStr = new String(cipherPrivateKeyCahe.doFinal(inputByte));
        } catch (Exception e) {
           //偶尔会报错，试了2万线程重试就不报错
            try {
                cipherPrivateKeyCahe.init(Cipher.DECRYPT_MODE, privateKeyCache);
                outStr = new String(cipherPrivateKeyCahe.doFinal(inputByte));
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        }
        return outStr;
    }

    private PublicKey getPubKey(String pubKey) {
        PublicKey publicKey = null;
        try {
            java.security.spec.X509EncodedKeySpec bobPubKeySpec = new java.security.spec.X509EncodedKeySpec(
                    new BASE64Decoder().decodeBuffer(pubKey));
            // RSA对称加密算法
            java.security.KeyFactory keyFactory;
            keyFactory = java.security.KeyFactory.getInstance("RSA");
            // 取公钥匙对象
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * 实例化私钥
     *
     * @return
     */
    private PrivateKey getPrivateKey(String priKey) {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec priPKCS8;
        try {
            priPKCS8 = new PKCS8EncodedKeySpec(
                    new BASE64Decoder().decodeBuffer(priKey));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            privateKey = keyf.generatePrivate(priPKCS8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    // public static void main(String[] args) {
    //     //生成公钥和私钥
    //     // genKeyPair();
    //     //加密字符串
    //     String message = "420684198702154579";
    //     String messageEn = encrypt(message, publicKey);
    //     System.out.println("加密后的字符串为:" + messageEn);
    //     String messageDe = decrypt(messageEn, privateKey);
    //     System.out.println("还原后的字符串为:" + messageDe);
    // }


    public static void main3(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        //明文
//        String ming = "hadoop@123";
        String ming = "420684198702154579!hadoop123420684198702154579";
        // 加密后的密文
        String mi = encrypt(ming, publicKey);

        // String mi = "F5Ig3S4kpefa1K8BOwanSghvEaBFn4qGO32EF9/GYDHhG+gOz/wwi2z0tL3DKzLfTxtAg/KpuShUw/iL5Nh6NQ==";
        System.err.println("mi=" + mi);
        // //解密后的明文
        // String ming2 = decrypt(mi, privateKey);
        // System.err.println("ming2=" + ming2);
        System.err.println(" 时长：" + (System.currentTimeMillis() - start));
    }

    public static void main4(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        //明文
//        String ming = "hadoop@123";
//         String ming = "42068419870hadoophadoophadoophadoophadoophadoop";
//         // 加密后的密文
//         String mi = encrypt(ming, publicKey);

        String mi = "F5Ig3S4kpefa1K8BOwanSghvEaBFn4qGO32EF9/GYDHhG+gOz/wwi2z0tL3DKzLfTxtAg/KpuShUw/iL5Nh6NQ==";
        System.err.println("mi=" + mi);
        //解密后的明文
        String ming2 = decrypt(mi);
        System.err.println("ming2=" + ming2);
        System.err.println(" 时长：" + (System.currentTimeMillis() - start));
    }

    public static void main(String[] args) {
        for (int i = 0; i <200; i++)
            new Thread() {
                @Override
                public void run() {
                    try {
                        main4(null);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }.start();
    }


}