package com.smartmining.test.ctl;

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
public class EncryptCtl {
    private static Logger log = LoggerFactory.getLogger(EncryptCtl.class);

    public EncryptCtl() {
        System.out.println("init Hello DemoCtl");
    }


    @RequestMapping(value = "/encrypt/loginRSA.do")
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
        return list;
    }

    //登录验证
    @RequestMapping(value = "/encrypt/textLogin.do")
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
        RSAPrivateKey privateKey = (RSAPrivateKey) request.getSession().getAttribute("privateKeyLogin");
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
    @RequestMapping(value = "/encrypt/md5.do")
    @ResponseBody
    public String testMd5(String md5, String text, HttpServletRequest request) {
        if (MD5Util.string2MD5(text).equals(md5)) {
            return "success";
        }
        return "fail";
    }

}
