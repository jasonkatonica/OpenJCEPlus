/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * This class generates a secret key for use with the AES algorithm.
 *
 * Key material is pre-buffered in a per-thread cache to reduce SecureRandom
 * call frequency on the generateKey() hot path. Each thread draws from its
 * own private buffer, eliminating lock contention entirely.
 */
public final class AESKeyGenerator extends KeyGeneratorSpi {

    /** Maximum AES key size in bytes (AES-256). */
    private static final int MAX_KEY_BYTES = 32;

    /**
     * Number of keys worth of random bytes to buffer per thread.
     * 1024 keys * 32 bytes = 32 KB per thread.
     * Larger buffer means less frequent SecureRandom calls; amortizes cost
     * across more generateKey() calls before the next refill.
     */
    private static final int BUFFER_KEYS = 1024;

    private static final int BUFFER_BYTES = BUFFER_KEYS * MAX_KEY_BYTES;

    private OpenJCEPlusProvider provider = null;
    private int keysize = 16; // default keysize (in bytes)
    private SecureRandom cryptoRandom = null;

    /**
     * Per-thread byte buffer of pre-generated random key material.
     * Each thread refills its own buffer from SecureRandom in one bulk call,
     * then draws individual key-sized chunks without any synchronization.
     */
    private final ThreadLocal<byte[]> threadBuffer = ThreadLocal.withInitial(
            () -> new byte[BUFFER_BYTES]);

    /** Per-thread read position within the thread buffer. */
    private final ThreadLocal<int[]> threadPos = ThreadLocal.withInitial(
            () -> new int[]{BUFFER_BYTES}); // start at end to trigger first refill

    /**
     * Constructor.
     *
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java provider the OpenJCEPlus provider
     */
    public AESKeyGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    /**
     * Generates an AES key.
     *
     * @return the new AES key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }

        byte[] buf = threadBuffer.get();
        int[] pos = threadPos.get();

        // Refill the thread-local buffer if exhausted.
        if (pos[0] + this.keysize > BUFFER_BYTES) {
            cryptoRandom.nextBytes(buf);
            pos[0] = 0;
        }

        // Copy key bytes from the thread-local buffer - no lock needed.
        byte[] keyBytes = Arrays.copyOfRange(buf, pos[0], pos[0] + this.keysize);
        // Zero the consumed region so key material is not retained in the buffer.
        Arrays.fill(buf, pos[0], pos[0] + this.keysize, (byte) 0x00);
        pos[0] += this.keysize;

        try {
            // Trusted constructor: AESKey takes ownership of keyBytes directly.
            return new AESKey(provider, keyBytes, true);
        } catch (InvalidKeyException e) {
            // Should never happen
            Arrays.fill(keyBytes, (byte) 0x00);
            throw new ProviderException(e.getMessage());
        }
        // keyBytes ownership transferred to AESKey - do not zero here.
    }

    /**
     * Initializes this key generator.
     *
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java random the source of randomness for this generator
     */
    @Override
    protected void engineInit(SecureRandom random) {
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
    }

    /**
     * Initializes this key generator with the specified parameter set and a
     * user-provided source of randomness.
     *
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java params the key generation parameters
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java random the source of randomness for this key generator
     * @src/test/java/ibm/jceplus/junit/tests/TestAESCipherInputStreamExceptions.java InvalidAlgorithmParameterException if params is inappropriate
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "AES key generation does not take any parameters");
    }

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     *
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java keysize the keysize in number of bits (128, 192, or 256)
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java random  the source of randomness for this key generator
     */
    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (((keysize % 8) != 0) || (!AESUtils.isKeySizeValid(keysize / 8))) {
            throw new InvalidParameterException("Wrong keysize: must be equal to 128, 192 or 256");
        }
        this.keysize = keysize / 8;
        this.engineInit(random);
    }
}
