/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.AESKeyWrap;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

abstract class AESKeyWrapCipher extends CipherSpi {

    private OpenJCEPlusProvider provider = null;
    private boolean wrappering = true;
    private boolean initialized = false;
    private AESKeyWrap cipher = null;
    private int setKeySize = 0;
    private boolean setPadding = false;

    public AESKeyWrapCipher(OpenJCEPlusProvider provider, boolean padding, int keySize) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }
        this.provider = provider;
        this.setKeySize = keySize;
        this.setPadding = padding;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    @Override
    protected int engineGetBlockSize() {
        return 8;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null || !key.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (!AESUtils.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + encoded.length + " bytes");
        }
        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int result = 0;
        if (!wrappering) {
            result = inputLen;
        } else {
            result = Math.addExact(inputLen, 16);
        }
        return (result < 0? 0:result);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;

        return params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

        if (opmode == Cipher.UNWRAP_MODE) {
            wrappering = false;
        } else if (opmode == Cipher.WRAP_MODE) {
            wrappering = true;
        } else {
            throw new UnsupportedOperationException("This cipher can " +
                "only be used for key wrapping and unwrapping");
        }

        internalInit(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    private void internalInit(int opmode, Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("AES"))) {
            throw new InvalidKeyException("Wrong algorithm: AES required");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("Key bytes are missing");
        }

        if (!checkKeySize(rawKey.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + rawKey.length + " bytes");
        }

        try {
            this.cipher = new AESKeyWrap(provider.getOCKContext(), rawKey, setPadding);
        } catch (Exception e) {
            throw new InvalidKeyException("OCKC context null or bad key.");
        } 
        this.initialized = true;   
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("KW") && !mode.equalsIgnoreCase("KWP")) {
            throw new NoSuchAlgorithmException("Only KW or KWP mode is supported.");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException(padding + " can not be used.");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();
        if (!wrappering) {
            throw new IllegalStateException("Cipher not initialized for wrap");
        }

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }

        try {
            return cipher.wrap(encoded, 0, encoded.length);
        } catch (Exception e) {
            // should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        checkCipherInitialized();

        if (wrappering) {
            throw new IllegalStateException("Cipher not initialized for wrap");
        }
        try {
            byte[] encoded = cipher.unwrap(wrappedKey, 0, wrappedKey.length);
            return ConstructKeys.constructKey(provider, encoded, algorithm, type);
        } catch (Exception e) {
            // should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        }    
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    private boolean checkKeySize(int keySize) {
        if ((!AESUtils.isKeySizeValid(keySize) || (keySize != setKeySize)) && (setKeySize != -1)) {
            return false;
        }
        return true;
    }
    public static final class KW extends AESKeyWrapCipher {

        public KW(OpenJCEPlusProvider provider) {
            super(provider, false, -1);
        }
    }

    public static final class KWP extends AESKeyWrapCipher {

        public KWP(OpenJCEPlusProvider provider) {
            super(provider, true, -1);
        }
    }
    
    public static final class KW_128 extends AESKeyWrapCipher {

        public KW_128(OpenJCEPlusProvider provider) {
            super(provider, false, 16);
        }
    }

    public static final class KWP_128 extends AESKeyWrapCipher {

        public KWP_128(OpenJCEPlusProvider provider) {
            super(provider, true, 16);
        }
    }
        
    public static final class KW_192 extends AESKeyWrapCipher {

        public KW_192(OpenJCEPlusProvider provider) {
            super(provider, false, 24);
        }
    }

    public static final class KWP_192 extends AESKeyWrapCipher {

        public KWP_192(OpenJCEPlusProvider provider) {
            super(provider, true, 24);
        }
    }
        
    public static final class KW_256 extends AESKeyWrapCipher {

        public KW_256(OpenJCEPlusProvider provider) {
            super(provider, false, 32);
        }
    }

    public static final class KWP_256 extends AESKeyWrapCipher {

        public KWP_256(OpenJCEPlusProvider provider) {
            super(provider, true, 32);
        }
    }
}
