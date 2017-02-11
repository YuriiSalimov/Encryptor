package com.salimov.yurii.Encryptor;

/**
 * The interface describes the methods for data encryption.
 *
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 * @version 1.0
 * @see Encryptor
 */
public interface IEncryptor {

    /**
     * Encrypts a data.
     *
     * @return The encrypted data.
     */
    String encrypt();

    /**
     * Decrypts a date.
     *
     * @return The decrypted data
     */
    String decrypt();

    /**
     * Returns a value to encrypt or to decrypt.
     *
     * @return The value to encrypt or to decrypt.
     */
    String getValue();
}
