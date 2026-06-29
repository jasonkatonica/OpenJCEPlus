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
import java.util.concurrent.ArrayBlockingQueue;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * This class generates a secret key for use with the AES algorithm.
 *
 * Key material is pre-generated asynchronously in a pool to reduce
 * SecureRandom latency on the generateKey() hot path.
 */
public final class AESKeyGenerator extends KeyGeneratorSpi {

    /** Pool capacity: number of pre-generated key slots. */
    private static final int POOL_CAPACITY = 64;

    /** Maximum AES key size in bytes (AES-256). */
    private static final int MAX_KEY_BYTES = 32;

    private OpenJCEPlusProvider provider = null;
    private int keysize = 16; // default keysize (in bytes)
    private SecureRandom cryptoRandom = null;

    /**
     * Pool of pre-generated random key material. Each element is a freshly
     * generated MAX_KEY_BYTES-length byte array. generateKey() takes from this
     * pool and copies the required keysize bytes. A background daemon thread
     * continuously refills the pool.
     */
    private ArrayBlockingQueue<byte[]> keyPool = null;

    /** Background refill thread. */
    private Thread refillThread = null;

    /**
     * Constructor.
     *
     * @src/test/java/ibm/jceplus/junit/openjceplusfips/TestECDHKeyAgreementParamValidation.java provider the OpenJCEPlus provider
     */
    public AESKeyGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    /**
     * Initialise the key material pool and start the background refill thread.
     * Called lazily once the SecureRandom is known. Synchronized to prevent
     * double-initialisation under concurrent first calls.
     */
    private synchronized void initPool() {
        if (keyPool != null) {
            return;
        }
        keyPool = new ArrayBlockingQueue<>(POOL_CAPACITY);

        // Pre-fill half the pool synchronously so initial calls hit the pool.
        for (int i = 0; i < POOL_CAPACITY / 2; i++) {
            byte[] slot = new byte[MAX_KEY_BYTES];
            cryptoRandom.nextBytes(slot);
            if (!keyPool.offer(slot)) {
                break;
            }
        }

        // Background daemon thread keeps pool full.
        refillThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    byte[] slot = new byte[MAX_KEY_BYTES];
                    cryptoRandom.nextBytes(slot);
                    keyPool.put(slot); // blocks when pool is full
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "AESKeyGenerator-pool-refill");
        refillThread.setDaemon(true);
        refillThread.start();
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

        if (keyPool == null) {
            initPool();
        }

        // Fast path: take pre-generated material from pool (non-blocking).
        byte[] poolSlot = keyPool.poll();
        byte[] keyBytes;
        if (poolSlot != null) {
            keyBytes = Arrays.copyOf(poolSlot, this.keysize);
            Arrays.fill(poolSlot, (byte) 0x00);
        } else {
            // Fallback: pool temporarily empty, generate directly.
            keyBytes = new byte[this.keysize];
            cryptoRandom.nextBytes(keyBytes);
        }

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
