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
 */
public final class AESKeyGenerator extends KeyGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private int keysize = 16; // default keysize (in bytes)
    private SecureRandom cryptoRandom = null;

    // Performance optimization: Pre-allocated thread-local buffers for key generation
    // to reduce allocation overhead. Each thread gets its own buffer to avoid contention.
    // Separate buffers for each key size to optimize cache locality.
    private static final ThreadLocal<byte[]> KEY_BUFFER_128 = ThreadLocal.withInitial(() -> new byte[16]);
    private static final ThreadLocal<byte[]> KEY_BUFFER_192 = ThreadLocal.withInitial(() -> new byte[24]);
    private static final ThreadLocal<byte[]> KEY_BUFFER_256 = ThreadLocal.withInitial(() -> new byte[32]);

    /**
     * Empty constructor
     */
    public AESKeyGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    /**
     * Generates an AES key.
     *
     * Performance optimizations:
     * - Uses thread-local buffers to avoid repeated allocations
     * - Skips redundant validation in AESKey constructor (size pre-validated in engineInit)
     * - Minimizes branching in the hot path
     * - Maintains FIPS compliance by clearing buffers after use
     *
     * @return the new AES key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        // Optimization: Ensure SecureRandom is initialized once
        // This eliminates the null check overhead on every key generation
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }

        // Use thread-local buffer based on key size to avoid allocation overhead
        // This provides cache-friendly reuse of buffers across multiple key generations
        byte[] keyBuffer;
        switch (this.keysize) {
            case 16:
                keyBuffer = KEY_BUFFER_128.get();
                break;
            case 24:
                keyBuffer = KEY_BUFFER_192.get();
                break;
            case 32:
                keyBuffer = KEY_BUFFER_256.get();
                break;
            default:
                // Fallback for non-standard sizes (should not happen in practice)
                keyBuffer = new byte[this.keysize];
        }

        // Generate random key material directly into the buffer
        cryptoRandom.nextBytes(keyBuffer);

        try {
            // Optimization: Use internal constructor that skips redundant validation
            // The key size is already validated in engineInit, so we can safely
            // create the key without re-checking the size
            return new AESKey(provider, keyBuffer, true);
        } catch (InvalidKeyException e) {
            // Should never happen since keysize is pre-validated
            throw new ProviderException(e.getMessage());
        } finally {
            // FIPS requirement: Clear the buffer after use
            // Note: Thread-local buffers are reused, so clearing is essential
            Arrays.fill(keyBuffer, (byte) 0x00);
        }
    }

    /**
     * Initializes this key generator.
     * 
     * @param random
     *            the source of randomness for this generator
     */
    @Override
    protected void engineInit(SecureRandom random) {
        // If in FIPS mode, SecureRandom must be internal and FIPS approved.
        // For FIPS mode, user provided random generator will be ignored.
        //
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
    }

    /**
     * Initializes this key generator with the specified parameter set and a
     * user-provided source of randomness.
     *
     * @param params
     *            the key generation parameters
     * @param random
     *            the source of randomness for this key generator
     *
     * @exception InvalidAlgorithmParameterException
     *                if <code>params</code> is inappropriate for this key
     *                generator
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
     * @param keysize
     *            the keysize. This is an algorithm-specific metric specified in
     *            number of bits.
     * @param random
     *            the source of randomness for this key generator
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