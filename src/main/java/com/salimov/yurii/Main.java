package com.salimov.yurii;

import com.salimov.yurii.encryptor.Base64Encryptor;
import com.salimov.yurii.encryptor.Encryptor;

/**
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 * @version 1.0
 */
public class Main {

    public static void main(String[] args) {
        final Encryptor encryptor = new Base64Encryptor();
        final String login = "admin";
        final String password = "password";
        System.out.println(encryptor.encrypt(login));
        System.out.println(encryptor.encrypt(password));
    }
}
