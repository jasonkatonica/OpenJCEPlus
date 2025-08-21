/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameters;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class BaseTestAESKeyWrap extends BaseTestJunit5Interop {

    protected SecretKey key;
    protected AlgorithmParameters params = null;
    protected Cipher cpA = null;
    protected Cipher cpB = null;
    protected boolean success = true;
    protected int specifiedKeySize = 0;

    @ParameterizedTest
    @CsvSource({"AES/KW/Nopadding","AES/KWP/Nopadding","AES_128/KW/Nopadding","AES_128/KWP/Nopadding","AES_192/KW/Nopadding","AES_192/KWP/Nopadding",
                "AES_256/KW/Nopadding","AES_256/KWP/Nopadding"})
    public void testAESWrap128Keys(String alg) throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;

        kek = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 128, getProviderName());

        WrapUnwrapKey(alg, keyToBeWrapped, kek, getProviderName());
    }
 
    @ParameterizedTest
    @CsvSource({"AES/KW/Nopadding","AES/KWP/Nopadding","AES_128/KW/Nopadding","AES_128/KWP/Nopadding","AES_192/KW/Nopadding","AES_192/KWP/Nopadding",
                "AES_256/KW/Nopadding","AES_256/KWP/Nopadding"})
    public void testAESWrapWith256WrappedKey(String alg) throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;

        kek = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getProviderName());

        WrapUnwrapKey(alg, keyToBeWrapped, kek, getProviderName());
    }

    @ParameterizedTest
    @CsvSource({"AES/KW/Nopadding","AES/KWP/Nopadding","AES_128/KW/Nopadding","AES_128/KWP/Nopadding","AES_192/KW/Nopadding","AES_192/KWP/Nopadding",
                "AES_256/KW/Nopadding","AES_256/KWP/Nopadding"})
    public void testAESWrapInterop(String alg) throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;

        kek = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        WrapUnwrapKeyInterop(alg, keyToBeWrapped, kek, getProviderName(), getInteropProviderName());

        kek = createKey("AES", getKeySize(alg), getInteropProviderName());
        keyToBeWrapped = createKey("AES", 256, getProviderName());

        WrapUnwrapKeyInteropRev(alg, keyToBeWrapped, kek, getProviderName(), getInteropProviderName());
    }
        
    @ParameterizedTest
    @CsvSource({"AES_192/KW/Nopadding","AES_192/KWP/Nopadding", "AES_256/KW/Nopadding","AES_256/KWP/Nopadding"})
    public void testAESWrapFailureKeySize(String alg) throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;

        kek = createKey("AES", 128, getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

       

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, kek);
            byte [] cipherText = cp.wrap(keyToBeWrapped);

            cp.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);
            fail("testAESWrapFailureKeySize did no fail as expected.");
        } catch (Exception e) {
            assumeTrue(true);
        }
    }

    @ParameterizedTest
    @CsvSource({"AES_192/KW/Nopadding","AES_192/KWP/Nopadding", "AES_256/KW/Nopadding","AES_256/KWP/Nopadding"})
    public void testAESWrapFailureCiphertext(String alg) throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;

        kek = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, kek);
            byte [] cipherText = cp.wrap(keyToBeWrapped);

            cipherText[2] = (byte)0xFF;

            cp.init(Cipher.UNWRAP_MODE, kek);

            cp.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);
            fail("testAESWrapFailureCiphertext did no fail as expected.");
        } catch (Exception e) {
            assumeTrue(true);
        }
    }

    @Test
    public void testAESWrapModeFailureWrap() throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;
        String alg = "AES_192/KW/Nopadding ";

        kek = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.UNWRAP_MODE, kek);
            cp.wrap(keyToBeWrapped);
            fail("testAESWrapModeFailureWrap did no fail as expected.");
        } catch (Exception e) {
            assumeTrue(true);
        }
    }

    @Test
    public void testAESWrapModeFailureUnwrap() throws Exception {
        SecretKey kek = null;
        SecretKey keyToBeWrapped = null;
        String alg = "AES_192/KW/Nopadding ";

        kek = createKey("AES", getKeySize(alg), getProviderName());
        keyToBeWrapped = createKey("AES", 256, getInteropProviderName());

        try {
            Cipher cp = null;

            cp = Cipher.getInstance(alg, getProviderName());

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, kek);
            byte [] cipherText = cp.wrap(keyToBeWrapped);
            cp.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);

            fail("testAESWrapModeFailureUnwrap did no fail as expected.");
        } catch (Exception e) {
            assumeTrue(true);
        }
    }

    public SecretKey createKey(String alg, int size, String providerName){
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(alg, providerName);
            keyGen.init(size);
        } catch (Exception ex) {
            assertFalse(true);
        }
        return keyGen.generateKey();
    }

    public void WrapUnwrapKey(String cipher, SecretKey keyWrapped, SecretKey KEK, String providerName) {

        Cipher cp = null;
        try {
            cp = Cipher.getInstance(cipher, providerName);

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, KEK);
            byte [] cipherText = cp.wrap(keyWrapped);

            cp.init(Cipher.UNWRAP_MODE, KEK);

            Key res = cp.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(), "Keys does not match!");

        } catch (Exception ex) {
            System.out.println("Test exception: "+ex.getMessage());
            ex.printStackTrace();
            assertFalse(true);
        }

    }

    public void WrapUnwrapKeyInterop(String cipher, SecretKey keyWrapped, SecretKey KEK, String providerName, String providerNameInterop) {

        Cipher cp          = null;
        Cipher cpI         = null;
        Key res            = null;
        byte [] cipherText = null;

        try {
            cp = Cipher.getInstance(cipher, providerName);
            cpI = Cipher.getInstance(cipher, providerNameInterop);

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, KEK);
            cipherText = cp.wrap(keyWrapped);

            cpI.init(Cipher.UNWRAP_MODE, KEK);

            res = cpI.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(), "Keys does not match!");  

            cipherText = null;
            res = null;
            // Encrypt the plain text
            cpI.init(Cipher.WRAP_MODE, KEK);
            cipherText = cpI.wrap(keyWrapped);

            cp.init(Cipher.UNWRAP_MODE, KEK);

            res = cp.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(), "Keys does not match!");
        } catch (Exception ex) {
            System.out.println("Test exception: "+ex.getMessage());
            assertFalse(true);
        }
    }

    public void WrapUnwrapKeyInteropRev(String cipher, SecretKey keyWrapped, SecretKey KEK, String providerName, String providerNameInterop) {

        Cipher cp          = null;
        Cipher cpI         = null;
        Key res            = null;
        byte [] cipherText = null;

        try {
            cp = Cipher.getInstance(cipher, providerNameInterop);
            cpI = Cipher.getInstance(cipher, providerName);

            // Encrypt the plain text
            cp.init(Cipher.WRAP_MODE, KEK);
            cipherText = cp.wrap(keyWrapped);

            cpI.init(Cipher.UNWRAP_MODE, KEK);

            res = cpI.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(), "Keys does not match!");  

            cipherText = null;
            res = null;
            // Encrypt the plain text
            cpI.init(Cipher.WRAP_MODE, KEK);
            cipherText = cpI.wrap(keyWrapped);

            cp.init(Cipher.UNWRAP_MODE, KEK);

            res = cp.unwrap(cipherText, "AES",  Cipher.SECRET_KEY);

            assertArrayEquals(res.getEncoded(), keyWrapped.getEncoded(), "Keys does not match!");
        } catch (Exception ex) {
            System.out.println("Test exception: "+ex.getMessage());
            assertFalse(true);
        }
    }

    public int getKeySize(String alg) {
        int size = 128;
        switch (alg) {
            case "AES/KW/Nopadding":
            case "AES/KWP/Nopadding":
            case "AES_128/KW/Nopadding":
            case "AES_128/KWP/Nopadding":
                break;
            case "AES_192/KW/Nopadding":
            case "AES_192/KWP/Nopadding":
                size = 192;
                break;
            default:
                size = 256;
                break;
        }
        return size;
    }
}
