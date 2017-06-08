package com.salimov.yurii.encryptor;

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
 */
public final class Base64Encryptor implements Encryptor {

    /**
     * Default key.
     */
    private final static String KEY = "SECRET_KEY";

    /**
     * Default secret key.
     */
    private final static SecretKey DEFAULT_KEY = new DESSecretKey(KEY.getBytes());

    /**
     * Name of a default supported Charset.
     */
    private final static String DEFAULT_CHARSET_NAME = "UTF8";

    /**
     * Primary encoding format.
     */
    private static SecretKey staticSecretKey = DEFAULT_KEY;

    /**
     * Name of a default supported Charset.
     */
    private static String staticCharsetName = DEFAULT_CHARSET_NAME;

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
     * Constructor.
     */
    public Base64Encryptor() {
        this(Base64Encryptor.staticSecretKey);
    }

    /**
     * Constructor.
     *
     * @param secretKey the primary encoding format.
     */
    public Base64Encryptor(final String secretKey) {
        this(secretKey.getBytes());
    }

    /**
     * Constructor.
     *
     * @param secretKey the primary encoding format.
     */
    public Base64Encryptor(final byte[] secretKey) {
        this(new DESSecretKey(secretKey));
    }

    /**
     * Constructor.
     *
     * @param secretKey the primary encoding format.
     */
    public Base64Encryptor(final SecretKey secretKey) {
        this(secretKey, Base64Encryptor.staticCharsetName);
    }

    /**
     * Constructor.
     *
     * @param secretKey   the primary encoding format.
     * @param charsetName the name of supported Charset.
     * @throws IllegalArgumentException Throw exception when
     *                                  input parameters is illegal.
     */
    public Base64Encryptor(final SecretKey secretKey, final String charsetName) throws IllegalArgumentException {
        try {
            this.encryptCipher = Cipher.getInstance(secretKey.getAlgorithm());
            this.encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            this.decryptCipher = Cipher.getInstance(secretKey.getAlgorithm());
            this.decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
            if (isNotEmpty(charsetName)) {
                this.charsetName = charsetName;
            } else {
                this.charsetName = Base64Encryptor.staticCharsetName;
            }
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage());
        }
    }

    /**
     * Encrypts a data.
     *
     * @param value the value to encrypt.
     * @return The encrypted data or empty string (newer null).
     */
    @Override
    public String encrypt(final String value) {
        String result;
        if (isNotEmpty(value)) {
            try {
                result = getEncryptedString(value);
            } catch (Exception ex) {
                logException(ex);
                result = "";
            }
        } else {
            result = "";
        }
        return result;
    }

    /**
     * Decrypts a date.
     *
     * @param value the value to decrypt.
     * @return The decrypted data or empty string (newer null).
     */
    @Override
    public String decrypt(final String value) {
        String result;
        if (isNotEmpty(value)) {
            try {
                result = getDecryptedString(value);
            } catch (Exception ex) {
                logException(ex);
                result = "";
            }
        } else {
            result = "";
        }
        return result;
    }

    /**
     * Sets a primary encoding format.
     *
     * @param secretKey the primary encoding format.
     */
    public static void setSecretKey(final String secretKey) {
        if (isNotEmpty(secretKey)) {
            setSecretKey(secretKey.getBytes());
        } else {
            setSecretKey(DEFAULT_KEY);
        }
    }

    /**
     * Sets a primary encoding format.
     *
     * @param secretKey the primary encoding format.
     */
    public static void setSecretKey(final byte[] secretKey) {
        if (isNotEmpty(secretKey)) {
            setSecretKey(new DESSecretKey(secretKey));
        } else {
            setSecretKey(DEFAULT_KEY);
        }
    }

    /**
     * Sets a primary encoding format.
     *
     * @param secretKey the primary encoding format.
     */
    public static void setSecretKey(final SecretKey secretKey) {
        if (isNotNull(secretKey)) {
            Base64Encryptor.staticSecretKey = secretKey;
        } else {
            Base64Encryptor.staticSecretKey = DEFAULT_KEY;
        }
    }

    /**
     * Sets name of a default supported Charset.
     *
     * @param charsetName the name of a default supported Charset.
     */
    public static void setCharsetName(final String charsetName) {
        if (isNotEmpty(charsetName)) {
            Base64Encryptor.staticCharsetName = charsetName;
        } else {
            Base64Encryptor.staticCharsetName = DEFAULT_CHARSET_NAME;
        }
    }

    /**
     * Encrypts a string and returns it.
     *
     * @return The encrypted string (newer null).
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
    private String getEncryptedString(final String value) throws BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        final byte[] valueBytes = value.getBytes(this.charsetName);
        final byte[] encryptBytes = this.encryptCipher.doFinal(valueBytes);
        return Base64.encodeBase64String(encryptBytes).replace("=", "");
    }

    /**
     * Decrypts a string and returns it.
     *
     * @return The decrypted string (newer null).
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
    private String getDecryptedString(final String value) throws BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        final byte[] decodeBytes = Base64.decodeBase64(value);
        final byte[] decryptBytes = this.decryptCipher.doFinal(decodeBytes);
        return new String(decryptBytes, this.charsetName).replace("=", "");
    }

    /**
     * Error logging.
     *
     * @param ex the intercepted exception.
     */
    private void logException(final Exception ex) {
        ex.printStackTrace();
    }

    /**
     * Checks if a CharSequence is not empty (""), not null and not whitespace only.
     * <pre>
     *     isNotEmpty(null) = false
     *     isNotEmpty("") = false
     *     isNotEmpty(" ") = false
     *     isNotEmpty("bob") = true
     *     isNotEmpty("  bob  ") = true
     * </pre>
     *
     * @param value the CharSequence to check, may be null
     * @return true if the CharSequence is not empty and not null
     * and not whitespace, false otherwise.
     */
    private static boolean isNotEmpty(final String value) {
        return isNotNull(value) && !value.isEmpty();
    }

    /**
     * Checks if a array is not null and not empty.
     * <pre>
     *     isNotEmpty(null) = false
     *     isNotEmpty(new byte[]{}) = false
     *     isNotEmpty(new byte[]{1}) = true
     *     isNotEmpty(new byte[]{1, 2, 3}) = true
     * </pre>
     *
     * @param bytes the array to check, may be null
     * @return true if the array is not null and not empty,
     * false otherwise.
     */
    private static boolean isNotEmpty(final byte[] bytes) {
        return isNotNull(bytes) && (bytes.length > 0);
    }

    /**
     * Checks if a Object is not null.
     * <pre>
     *     isNotNull(null) = false
     *     isNotNull(new Object()) = true
     * </pre>
     *
     * @param object the Object to check, may be null
     * @return true if the Object is not null, false otherwise.
     */
    private static boolean isNotNull(final Object object) {
        return (object != null);
    }
}
