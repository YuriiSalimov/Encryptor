package com.salimov.yurii.encryptor;

import javax.crypto.SecretKey;
import java.util.Arrays;

/**
 * Class describes DES secret key.
 *
 * @author Yuriy Salimov (yuriy.alex.salimov@gmail.com)
 */
final class DESSecretKey implements SecretKey {

    /**
     * Algorithm of the secret key.
     */
    private static final String ALGORITHM = "DES";

    /**
     * Format of the secret key.
     */
    private static final String FORMAT = "RAW";

    /**
     * Primary encoding format.
     */
    private final byte[] key;

    /**
     * Constructor.
     *
     * @param key the primary encoding format.
     */
    DESSecretKey(final byte[] key) {
        if (key.length > 8) {
            this.key = Arrays.copyOf(key, 8);
        } else {
            this.key = Arrays.copyOf(key, key.length);
        }
    }

    /**
     * Returns a string representation of the object.
     *
     * @return A string representation of the object.
     */
    @Override
    public String toString() {
        return "DESSecretKey{" +
                "key=" + Arrays.toString(key) +
                ", Algorithm=" + ALGORITHM +
                ", Format=" + FORMAT +
                '}';
    }

    /**
     * Indicates whether some other object is "equal to" this one.
     *
     * @param object The reference object with which to compare.
     * @return true if this object is the same as the object
     * argument, false otherwise otherwise.
     */
    @Override
    public boolean equals(final Object object) {
        if (this == object) {
            return true;
        }
        if ((object == null) || (this.getClass() != object.getClass())) {
            return false;
        }
        final DESSecretKey other = (DESSecretKey) object;
        return Arrays.equals(this.key, other.key);

    }

    /**
     * Returns a hash code value for the object.
     * This method is supported for the benefit
     * of hash tables such as those provided by HashMap.
     *
     * @return A hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(this.key);
    }

    /**
     * Returns the standard algorithm name for this key.
     *
     * @return the name of the algorithm associated with this key.
     */
    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    /**
     * Returns the name of the primary encoding format.
     *
     * @return The primary encoding format of the key.
     */
    @Override
    public String getFormat() {
        return FORMAT;
    }

    /**
     * Returns the name of the primary encoding format.
     *
     * @return The primary encoding format of the key.
     */
    @Override
    public byte[] getEncoded() {
        return this.key;
    }
}
