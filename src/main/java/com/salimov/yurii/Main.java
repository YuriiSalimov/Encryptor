package com.salimov.yurii;

import com.salimov.yurii.encryptor.Base64Encryptor;
import com.salimov.yurii.encryptor.Encryptor;

import java.security.NoSuchAlgorithmException;

/**
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 */
public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Encryptor encryptor = new Base64Encryptor();

        final String login = "admin";
        final String enLogin = encryptor.encrypt(login);
        final String decLogin = encryptor.decrypt(enLogin);
        System.out.println(login + " - " + enLogin + " - " + decLogin);

        final String password = "password";
        final String enPass = encryptor.encrypt(password);
        final String decPass = encryptor.decrypt(enPass);
        System.out.println(password + " - " + enPass + " - " + decPass);
    }
}
