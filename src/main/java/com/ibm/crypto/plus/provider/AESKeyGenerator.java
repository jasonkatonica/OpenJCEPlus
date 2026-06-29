/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
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
 * <p>Key material is pre-generated asynchronously in a pool to reduce
 * SecureRandom latency on the hot path.
 */
public final class AESKeyGenerator extends KeyGeneratorSpi {

    /** Pool capacity: number of pre-generated key slots. */
    private static final int POOL_CAPACITY = 64;

    /** Maximum AES key size in bytes. */
    private static final int MAX_KEY_BYTES = 32;

    private OpenJCEPlusProvider provider = null;
    private int keysize = 16; // default keysize (in bytes)
    private SecureRandom cryptoRandom = null;

    /**
     * Pool of pre-generated random key material. Each element is a freshly
     * generated MAX_KEY_BYTES-length byte array filled with SecureRandom data.
     * generateKey() takes from this pool and slices the required keysize bytes.
     * A background daemon thread continuously refills the pool.
     */
    private ArrayBlockingQueue<byte[]> keyPool = null;

    /** Background refill thread. */
    private Thread refillThread = null;

    /**
     * Empty constructor
     */
    public AESKeyGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    /**
     * Initialise the key material pool and start the background refill thread.
     * Called once the SecureRandom is known.
     */
    private synchronized void initPool() {
        if (keyPool != null) {
            return; // already initialised
        }
        keyPool = new ArrayBlockingQueue<>(POOL_CAPACITY);

        // Pre-fill the pool synchronously for the first POOL_CAPACITY/2 slots
        // so the first generateKey() calls hit the pool immediately.
        for (int i = 0; i < POOL_CAPACITY / 2; i++) {
            byte[] slot = new byte[MAX_KEY_BYTES];
            cryptoRandom.nextBytes(slot);
            if (!keyPool.offer(slot)) {
                break; // pool full
            }
        }

        // Start background daemon thread to keep the pool full.
        refillThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    // Only generate when pool has room; blocking put keeps
                    // the thread sleeping when pool is already full.
                    byte[] slot = new byte[MAX_KEY_BYTES];
                    cryptoRandom.nextBytes(slot);
                    keyPool.put(slot); // blocks until space available
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

        // Ensure pool is initialised (lazy, thread-safe via synchronized initPool)
        if (keyPool == null) {
            initPool();
        }

        // Try to get pre-generated key material from the pool (non-blocking).
        byte[] poolSlot = keyPool.poll();

        byte[] keyBytes;
        if (poolSlot != null) {
            // Fast path: copy the needed bytes from the pooled slot.
            // The slot always has MAX_KEY_BYTES; we only need keysize bytes.
            keyBytes = Arrays.copyOf(poolSlot, this.keysize);
            // Zero out the pool slot so it is not reachable with key material.
            Arrays.fill(poolSlot, (byte) 0x00);
        } else {
            // Fallback: pool is temporarily empty, generate directly.
            keyBytes = new byte[this.keysize];
            cryptoRandom.nextBytes(keyBytes);
        }

        try {
            // Trusted constructor: AESKey takes ownership of keyBytes,
            // no internal defensive copy needed.
            return new AESKey(provider, keyBytes, true);
        } catch (java.security.InvalidKeyException e) {
            // Should never happen
            Arrays.fill(keyBytes, (byte) 0x00);
            throw new ProviderException(e.getMessage());
        }
        // keyBytes ownership transferred to AESKey — do not zero here.
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
