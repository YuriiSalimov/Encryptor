package com.salimov.yurii.encryptor;

import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * @author Yurii Salimov (yuriy.alex.salimov@gmail.com)
 */
public class DESSecretKeyTest {

    private final static String ANY_STRING = "Some unknown text.";

    private static DESSecretKey secretKey;

    @BeforeClass
    public static void beforeClass() {
        final byte[] key = ANY_STRING.getBytes();
        secretKey = new DESSecretKey(key);
    }

    @Test
    public void whenAddSmallBytesInConstructorThenUseIt() {
        final byte[] smallKey = { 1, 2, 3, 4, 5, 6, 7, 8 };
        final DESSecretKey secretKey = new DESSecretKey(smallKey);
        final byte[] encoded = secretKey.getEncoded();
        assertTrue(Arrays.equals(encoded, smallKey));
    }

    @Test
    public void whenAddSmallBytesInConstructorThenSubstringIt() {
        final byte[] smallKey = { 1, 2, 3, 4, 5, 6, 7, 8 };
        final byte[] bigKey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        final DESSecretKey secretKey = new DESSecretKey(bigKey);
        final byte[] encoded = secretKey.getEncoded();
        assertTrue(Arrays.equals(encoded, smallKey));
    }

    @Test
    public void toStringTest() {
        final String toStringTest = "DESSecretKey{" +
                "key=" + Arrays.toString(secretKey.getEncoded()) +
                ", Algorithm=" + secretKey.getAlgorithm() +
                ", Format=" + secretKey.getFormat() +
                '}';
        assertEquals(secretKey.toString(), toStringTest);
    }

    @Test
    public void equalsWithThisObjectThenReturnTrue() throws Exception {
        assertTrue(secretKey.equals(secretKey));
    }

    @Test
    public void equalsWithNull() throws Exception {
        assertFalse(secretKey.equals(null));
    }

    @Test
    public void equalsWithObjectOfTheAnotherClass() throws Exception {
        assertFalse(secretKey.equals(ANY_STRING));
    }

    @Test
    public void equalsTwoObjects() throws Exception {
        final byte[] key = { 1, 2, 3, 4, 5, 6, 7, 8 };
        final DESSecretKey first = new DESSecretKey(key);
        final DESSecretKey second = new DESSecretKey(key);
        for (int i = 0; i < 5; i++) {
            assertTrue(first.equals(second));
            assertTrue(second.equals(first));
        }
    }

    @Test
    public void equalsThreeObjects() throws Exception {
        final byte[] key = { 1, 2, 3, 4, 5, 6, 7, 8 };
        final DESSecretKey first = new DESSecretKey(key);
        final DESSecretKey second = new DESSecretKey(key);
        final DESSecretKey third = new DESSecretKey(key);
        for (int i = 0; i < 5; i++) {
            assertTrue(first.equals(second));
            assertTrue(second.equals(third));
            assertTrue(third.equals(first));
        }
    }

    @Test
    public void hashCodeTest() throws Exception {
        int hashCode = secretKey.hashCode();
        for (int i = 0; i < 5; i++) {
            int temp = secretKey.hashCode();
            assertEquals(temp, hashCode);
            hashCode = temp;
        }
    }

    @Test
    public void whenGetAlgorithmThenReturnEmpty() {
        final String algorithm = secretKey.getAlgorithm();
        assertFalse(algorithm.isEmpty());
    }

    @Test
    public void whenGetFormatThenReturnEmpty() {
        final String format = secretKey.getFormat();
        assertFalse(format.isEmpty());
    }

    @Test
    public void whenGetEncodedThenReturnEmpty() {
        final byte[] encoded = secretKey.getEncoded();
        assertTrue(encoded.length > 0);
    }
}
