package com.salimov.yurii.encryptor;

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

/**
 * @author Yurii Salimov (yuriy.alex.salimov@gmail.com)
 */
public class Base64EncryptorTest {

    private final static String ANY_STRING = "Some unknown text.";

    private static Encryptor encryptor;

    @BeforeClass
    public static void beforeClass() {
        encryptor = new Base64Encryptor();
    }

    @Test
    public void whenDefaultConstructorThenReturnNotNull() {
        assertNotNull(encryptor);
    }

    @Test
    public void whenConstructorWithOneStringParameter() {
        final Base64Encryptor encryptor = new Base64Encryptor(ANY_STRING);
        assertNotNull(encryptor);
    }

    @Test
    public void whenConstructorWithOneBytesParameter() {
        final byte[] secretKey = ANY_STRING.getBytes();
        final Base64Encryptor encryptor = new Base64Encryptor(secretKey);
        assertNotNull(encryptor);
    }

    @Test
    public void whenConstructorWithOneSecretKeyParameter() {
        final byte[] bytes = ANY_STRING.getBytes();
        final SecretKey secretKey = new DESSecretKey(bytes);
        final Base64Encryptor encryptor = new Base64Encryptor(secretKey);
        assertNotNull(encryptor);
    }

    @Test
    public void whenConstructorWithTwoStringsParameter() {
        final Base64Encryptor encryptor = new Base64Encryptor(ANY_STRING, ANY_STRING);
        assertNotNull(encryptor);
    }

    @Test
    public void whenConstructorWithSecretKeyAndStringParameter() {
        final byte[] bytes = ANY_STRING.getBytes();
        final SecretKey secretKey = new DESSecretKey(bytes);
        final Base64Encryptor encryptor = new Base64Encryptor(secretKey, ANY_STRING);
        assertNotNull(encryptor);
    }

    @Test
    public void whenEncryptThenReturnNotEmpty() {
        final String encryptedString = encryptor.encrypt(ANY_STRING);
        assertFalse(encryptedString.isEmpty());
    }

    @Test
    public void whenEncryptNullThenReturnEmpty() {
        final String encryptedString = encryptor.encrypt(null);
        assertTrue(encryptedString.isEmpty());
    }

    @Test
    public void whenEncryptEmptyThenReturnEmpty() {
        final String encryptedString = encryptor.encrypt("");
        assertTrue(encryptedString.isEmpty());
    }

    @Test
    public void whenDecryptThenReturnNotEmpty() {
        final String encryptedString = encryptor.encrypt(ANY_STRING);
        final String decryptedString = encryptor.decrypt(encryptedString);
        assertFalse(decryptedString.isEmpty());
    }

    @Test
    public void whenDecryptNullThenReturnEmpty() {
        final String decryptedString = encryptor.decrypt(null);
        assertTrue(decryptedString.isEmpty());
    }

    @Test
    public void whenDecryptEmptyThenReturnEmpty() {
        final String decryptedString = encryptor.decrypt("");
        assertTrue(decryptedString.isEmpty());
    }

    @Test
    public void whenEncryptAndDecryptEqualsValue() {
        final String encryptedString = encryptor.encrypt(ANY_STRING);
        final String decryptedString = encryptor.decrypt(encryptedString);
        assertEquals(ANY_STRING, decryptedString);
    }
}
