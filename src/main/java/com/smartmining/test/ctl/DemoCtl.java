package com.smartmining.test.ctl;

import com.alibaba.fastjson.JSON;
import com.smartmining.test.encrypt.MD5Util;
import com.smartmining.test.encrypt.RSAUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@RestController
public class DemoCtl {
    private static Logger log = LoggerFactory.getLogger(DemoCtl.class);

    public DemoCtl() {
        System.out.println("init Hello DemoCtl");
    }

    @RequestMapping("/hello")
    public String index() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        System.out.println("hello world!");
        return "Hello World! " + sdf.format(new Date());
    }

    @RequestMapping(value = "/UserText/loginRSA.do")
    @ResponseBody
    public List<String> loginRSA(HttpServletRequest request) {
        // HttpServletRequest request = ServletActionContext.getRequest();
        String publicKeyExponent = "";
        String publicKeyModulus = "";

        try {
            HashMap<String, Object> map = RSAUtils.getKeys();
            //生成公钥和私钥
            RSAPublicKey publicKey = (RSAPublicKey) map.get("public");
            RSAPrivateKey privateKey = (RSAPrivateKey) map.get("private");
            //私钥保存在session中，用于解密
            request.getSession().setAttribute("publicKeyLogin", publicKey);
            request.getSession().setAttribute("privateKeyLogin", privateKey);
            //公钥信息保存在页面，用于加密 公钥指数
            publicKeyExponent = publicKey.getPublicExponent().toString(16);
            System.out.println("zoule1:" + publicKeyExponent);
            //模
            publicKeyModulus = publicKey.getModulus().toString(16);
            System.out.println("zoule2:" + publicKeyModulus);

            // request.getSession().setAttribute("publicKeyExponent", publicKeyExponent);
            //request.getSession().setAttribute("publicKeyModulus", publicKeyModulus);
        } catch (Exception e) {
            log.error("RSA生成公钥错误", e);
        }
        List<String> list = new ArrayList<String>();
        list.add(publicKeyExponent);
        list.add(publicKeyModulus);
        System.out.println(JSON.toJSONString(list));
        return list;
    }


    //登录验证
    @RequestMapping(value = "/UserText/textLogin.do")
    @ResponseBody
    public String textLogin(String username, String password, HttpServletRequest request) {
        if ("".equals(username)) {
            System.out.println("the username is null");
            return "usernameIsNull";
        }
        if ("".equals(password)) {
            System.out.println("the password is null");
            return "passwordIsNull";
        }
        RSAPublicKey publicKey =(RSAPublicKey) request.getSession().getAttribute("publicKeyLogin");
        RSAPrivateKey privateKey = (RSAPrivateKey) request.getSession().getAttribute("privateKeyLogin");

        //公钥指数
        String public_exponent = publicKey.getPublicExponent().toString();
        System.out.println("pubkey exponent=" + public_exponent);
        //私钥指数
        // String private_exponent = privateKey1.getPrivateExponent().toString();
        // System.out.println("private exponent=" + private_exponent);
        // RSAPrivateKey privateKey = RSAUtils.getPrivateKey(public_exponent, private_exponent);
        try {
            username = RSAUtils.decryptByPrivateKey(username, privateKey);
            System.out.println("解密后1" + username);
            password = RSAUtils.decryptByPrivateKey(password, privateKey);
            System.out.println("解密后2" + password);
        } catch (Exception e) {
            log.error("RSA解密失败", e);
        }
//        User user = userService.getUser(username);
        //
        // String testpwd = "11";
//
//         if (password.equals(testpwd)) {
//             System.out.println("登陆成功");
//             return "success";
//         }
//         System.out.println("登录失败");
//         return "fail";
        return password;

    }

    //登录验证
    @RequestMapping(value = "/UserText/md5.do")
    @ResponseBody
    public String testMd5(String md5, String text, String miwen,HttpServletRequest request) throws Exception {
        System.out.println("解密前:\n" +miwen);
        RSAPrivateKey privateKey = (RSAPrivateKey) request.getSession().getAttribute("privateKeyLogin");
        miwen = RSAUtils.decryptByPrivateKey(miwen, privateKey);
        System.out.println("解密后:\n" + miwen);
        if (MD5Util.string2MD5(text).equals(md5)) {
            return "success";
        }
        return "fail";
    }

    //模
    public static final String publicModulus = "264210013287552459479809550268576539053";
    //公钥指数
    public static final String publicKeyExponent = "65537";
    //私钥指数
    public static final String privateKeyExponent = "2226375632666293021189009311435762497";


    /*
  public:{"algorithm":"RSA","encoded":"MCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAKhn85bcrAmNo71MKt/gq/8CAwEAAQ==","format":"X.509","modulus":223850050446347700904899447365826554879,"publicExponent":65537}
private:{"algorithm":"RSA","bagAttributeKeys":[],"crtCoefficient":15577752994125075938,"destroyed":false,"encoded":"MHgCAQAwDQYJKoZIhvcNAQEBBQAEZDBiAgEAAhEAqGfzltysCY2jvUwq3+Cr/wIDAQABAhAMYhBsUG+qCAxI8v4ulhVpAgkA9Dgby8wpcxsCCQCwh54rdrkU7QIIY+2RchJX44ECCGbsu6D12NXFAgkA2C9L0E2aVeI=","format":"PKCS#8","modulus":223850050446347700904899447365826554879,"primeExponentP":7200571298355340161,"primeExponentQ":7416508986366154181,"primeP":17597846106067792667,"primeQ":12720309582043878637,"privateExponent":16459914141644408052163010888428033385,"publicExponent":65537}
pubkey modulus=223850050446347700904899447365826554879
pubkey exponent=65537
private exponent=16459914141644408052163010888428033385
mi=A0E8E9A2D29FB1744368910CF8B437833ED7E550E0EC9FBF815C14CB2B8F5F9A
ming2=123456
   */
    private String privatekey="{\"algorithm\":\"RSA\",\"bagAttributeKeys\":[],\"crtCoefficient\":15577752994125075938,\"destroyed\":false,\"encoded\":\"MHgCAQAwDQYJKoZIhvcNAQEBBQAEZDBiAgEAAhEAqGfzltysCY2jvUwq3+Cr/wIDAQABAhAMYhBsUG+qCAxI8v4ulhVpAgkA9Dgby8wpcxsCCQCwh54rdrkU7QIIY+2RchJX44ECCGbsu6D12NXFAgkA2C9L0E2aVeI=\",\"format\":\"PKCS#8\",\"modulus\":223850050446347700904899447365826554879,\"primeExponentP\":7200571298355340161,\"primeExponentQ\":7416508986366154181,\"primeP\":17597846106067792667,\"primeQ\":12720309582043878637,\"privateExponent\":16459914141644408052163010888428033385,\"publicExponent\":65537}";


    //登录验证
    @RequestMapping(value = "/UserText/textCheck.do")
    @ResponseBody
    public String textLogin(String password, HttpServletRequest request) {

        if ("".equals(password)) {
            System.out.println("the password is null");
            return "passwordIsNull";
        }
        // RSAPrivateKey privateKey = (RSAPrivateKey) request.getSession().getAttribute("privateKeyLogin");
        // RSAPrivateKey privateKey = RSAUtils.getPrivateKey(publicModulus, privateKeyExponent);
        // RSAPrivateKey privateKey= JSON.toJavaObject((JSON) JSON.parse(privatekey),RSAPrivateKey.class);

        RSAPublicKey pubKey = RSAUtils.getPublicKey("195687463422972263025509210884120748537", "65537");
        RSAPrivateKey priKey = RSAUtils.getPrivateKey("195687463422972263025509210884120748537", "152776977180826080054453652913840207513");
        try {
            password = RSAUtils.decryptByPrivateKey(password, priKey);
            System.out.println("解密后2" + password);
        } catch (Exception e) {
            log.error("RSA解密失败", e);
        }

        return password;

    }


}
