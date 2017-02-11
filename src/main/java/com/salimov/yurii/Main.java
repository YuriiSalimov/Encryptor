package com.salimov.yurii;

import com.salimov.yurii.Encryptor.Encryptor;

/**
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 * @version 1.0
 */
public class Main {

    public static void main(String[] args) {
        String login = "SomeLogin";
        String encLogin = new Encryptor(login).encrypt();
        String decLogin = new Encryptor(encLogin).decrypt();
        System.out.println(login + " -> " + encLogin + " -> " + decLogin);

        String password = "SomePassword";
        String encPassword= new Encryptor(password).encrypt();
        String decPassword = new Encryptor(encPassword).decrypt();
        System.out.println(password + " -> " + encPassword + " -> " + decPassword);
    }
}
