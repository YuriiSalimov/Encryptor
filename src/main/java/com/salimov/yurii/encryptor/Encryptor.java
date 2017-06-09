package com.salimov.yurii.encryptor;

/**
 * The interface describes the methods for data encryption.
 *
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 */
public interface Encryptor {

    /**
     * Encrypts a data.
     *
     * @param value the value to encrypt.
     * @return The encrypted data.
     */
    String encrypt(String value);

    /**
     * Decrypts a date.
     *
     * @return The decrypted data
     */

    /**
     * Decrypts a date.
     *
     * @param value the value to decrypt.
     * @return The decrypted data.
     */
    String decrypt(String value);
}
