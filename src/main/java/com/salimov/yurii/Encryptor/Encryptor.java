package com.salimov.yurii.Encryptor;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;

/**
 * The class implements methods for data encryption.
 *
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 * @version 1.0
 * @see IEncryptor
 */
public final class Encryptor implements IEncryptor {

    /**
     * Default primary encoding format.
     */
    private final static SecretKey DEFAULT_KEY;

    /**
     * Name of a default supported Charset.
     */
    private final static String DEFAULT_CHARSET_NAME;

    /**
     * Primary encoding format.
     */
    private static SecretKey staticSecretKey;

    /**
     * Name of a default supported Charset.
     */
    private static String staticCharsetName;

    /**
     * Name of a supported Charset.
     */
    private final String charsetName;

    /**
     * Encrypt cipher.
     */
    private final Cipher encryptCipher;

    /**
     * Decrypt cipher.
     */
    private final Cipher decryptCipher;

    /**
     * The value to encrypt or to decrypt.
     */
    private final String value;

    /**
     * Static block.
     */
    static {
        DEFAULT_KEY = new DESSecretKey(
                ("SoMeSeCrEtKeY").getBytes()
        );
        DEFAULT_CHARSET_NAME = "UTF8";
        staticSecretKey = DEFAULT_KEY;
        staticCharsetName = DEFAULT_CHARSET_NAME;
    }

    /**
     * Constructor.
     *
     * @param value a value to encrypt or to decrypt.
     */
    public Encryptor(final String value) {
        this(value, Encryptor.staticSecretKey);
    }

    /**
     * Constructor.
     *
     * @param value     a value to encrypt or to decrypt.
     * @param secretKey a primary encoding format.
     */
    public Encryptor(final String value, final String secretKey) {
        this(value, secretKey.getBytes());
    }

    /**
     * Constructor.
     *
     * @param value     a value to encrypt or to decrypt.
     * @param secretKey a primary encoding format.
     */
    public Encryptor(final String value, final byte[] secretKey) {
        this(value, new DESSecretKey(secretKey));
    }

    /**
     * Constructor.
     *
     * @param value     a value to encrypt or to decrypt.
     * @param secretKey a primary encoding format.
     */
    public Encryptor(final String value, final SecretKey secretKey) {
        this(value, secretKey, Encryptor.staticCharsetName);
    }

    /**
     * Constructor.
     *
     * @param value       a value to encrypt or to decrypt.
     * @param secretKey   a primary encoding format.
     * @param charsetName a name of supported Charset.
     * @throws IllegalArgumentException Throw exception when
     *                                  input parameters is illegal.
     */
    public Encryptor(
            final String value,
            final SecretKey secretKey,
            final String charsetName
    ) throws IllegalArgumentException {
        try {
            this.value = value;
            this.encryptCipher = Cipher.getInstance(secretKey.getAlgorithm());
            this.encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            this.decryptCipher = Cipher.getInstance(secretKey.getAlgorithm());
            this.decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
            if (charsetName != null) {
                this.charsetName = charsetName;
            } else {
                this.charsetName = Encryptor.staticCharsetName;
            }
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage());
        }
    }

    /**
     * Encrypts a data.
     *
     * @return The encrypted data.
     */
    @Override
    public String encrypt() {
        String result;
        try {
            result = getEncryptedString();
        } catch (Exception ex) {
            ex.printStackTrace();
            result = null;
        }
        return result;
    }

    /**
     * Decrypts a date.
     *
     * @return The decrypted data
     */
    @Override
    public String decrypt() {
        String result;
        try {
            result = getDecryptedString();
        } catch (Exception ex) {
            ex.printStackTrace();
            result = null;
        }
        return result;
    }

    /**
     * Returns a value to encrypt or to decrypt.
     *
     * @return The value to encrypt or to decrypt.
     */
    @Override
    public String getValue() {
        return this.value;
    }

    /**
     * Sets a primary encoding format.
     *
     * @param secretKey a primary encoding format.
     */
    public static void setSecretKey(final String secretKey) {
        if (secretKey != null) {
            setSecretKey(secretKey.getBytes());
        } else {
            setSecretKey(DEFAULT_KEY);
        }
    }

    /**
     * Sets a primary encoding format.
     *
     * @param secretKey a primary encoding format.
     */
    public static void setSecretKey(final byte[] secretKey) {
        if ((secretKey != null) && (secretKey.length > 0)) {
            Encryptor.staticSecretKey = new DESSecretKey(secretKey);
        } else {
            Encryptor.staticSecretKey = DEFAULT_KEY;
        }
    }

    /**
     * Sets a primary encoding format.
     *
     * @param secretKey a primary encoding format.
     */
    public static void setSecretKey(final SecretKey secretKey) {
        if (secretKey != null) {
            Encryptor.staticSecretKey = secretKey;
        } else {
            Encryptor.staticSecretKey = DEFAULT_KEY;
        }
    }

    /**
     * Sets name of a default supported Charset.
     *
     * @param charsetName a name of a default supported Charset.
     */
    public static void setCharsetName(final String charsetName) {
        if (charsetName != null) {
            Encryptor.staticCharsetName = charsetName;
        } else {
            Encryptor.staticCharsetName = DEFAULT_CHARSET_NAME;
        }
    }

    /**
     * Encrypts a string and returns it.
     *
     * @return The encrypted string.
     * @throws BadPaddingException          if this cipher is in decryption mode,
     *                                      and (un)padding has been requested,
     *                                      but the decrypted data is not bounded
     *                                      by the appropriate padding bytes
     * @throws IllegalBlockSizeException    if this cipher is a block cipher,
     *                                      no padding has been requested (only
     *                                      in encryption mode), and the total
     *                                      input length of the data processed
     *                                      by this cipher is not a multiple of
     *                                      block size; or if this encryption
     *                                      algorithm is unable to process the
     *                                      input data provided.
     * @throws UnsupportedEncodingException If the named charset is not supported.
     */
    private String getEncryptedString() throws BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        return Base64.encodeBase64String(
                this.encryptCipher.doFinal(
                        this.value.getBytes(this.charsetName)
                )
        ).replace("=", "");
    }

    /**
     * Decrypts a string and returns it.
     *
     * @return The decrypted string.
     * @throws BadPaddingException          if this cipher is in decryption mode,
     *                                      and (un)padding has been requested,
     *                                      but the decrypted data is not bounded
     *                                      by the appropriate padding bytes
     * @throws IllegalBlockSizeException    if this cipher is a block cipher,
     *                                      no padding has been requested (only
     *                                      in encryption mode), and the total
     *                                      input length of the data processed
     *                                      by this cipher is not a multiple of
     *                                      block size; or if this encryption
     *                                      algorithm is unable to process the
     *                                      input data provided.
     * @throws UnsupportedEncodingException If the named charset is not supported.
     */
    private String getDecryptedString() throws BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        return new String(
                this.decryptCipher.doFinal(
                        Base64.decodeBase64(this.value)
                ),
                this.charsetName
        ).replace("=", "");
    }
}
