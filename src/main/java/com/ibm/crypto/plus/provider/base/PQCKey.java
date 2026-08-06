/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.PrimitiveWrapper;
import java.util.Arrays;

public final class PQCKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    // PrimitiveWrapper.Long is used so the cleaner lambda can zero the id
    // after calling MLKEY_delete.  Once zeroed, any subsequent getPKeyId()
    // call returns 0, which validId() rejects — giving a clean exception
    // instead of a silent use-after-free on a recycled native address.
    private PrimitiveWrapper.Long pkeyId = new PrimitiveWrapper.Long(0);
    private String algName;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private final static String badIdMsg = "Key Identifier is not valid";

    /**
     * Generates a keypair natively and returns a PQCKey that holds only the
     * already-extracted private and public key bytes.  The raw keypair EVP_PKEY*
     * returned by MLKEY_generate is freed <em>before</em> this method returns,
     * so its native address can never be reused while the caller still holds
     * derived keys that were created from those bytes.
     *
     * <p>Previously a PQCKey wrapper was returned for the raw keypair pointer.
     * That wrapper had no Java owner after generateKeyPair() returned, so the
     * GC could collect it immediately and the cleaner would free the native
     * address.  The allocator could then hand the same address to the very next
     * MLKEY_generate call.  If a decapsulation was in progress on a derived key
     * whose pkeyId happened to equal the recycled address, it would read from
     * the wrong (or partially overwritten) EVP_PKEY* and produce the wrong
     * shared secret — the intermittent "Secrets do NOT match" failure.</p>
     */
    public static PQCKey generateKeyPair(String algName, OpenJCEPlusProvider provider)
            throws NativeException {
        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = NativeCryptoSelector.selectBackend(provider, "KeyPairGenerator", algName);
        long keyId = 0;
        try {
            String NoDashAlg = algName.replace('-', '_');
            keyId = nativeInterface.MLKEY_generate(NoDashAlg);
            if (keyId == 0) {
                throw new NativeException("PQCKey.generateKeyPair: MLKEY_generate failed");
            }

            // Extract both byte arrays while the keypair is still alive.
            byte[] privateKeyBytes = nativeInterface.MLKEY_getPrivateKeyBytes(keyId);
            byte[] publicKeyBytes  = nativeInterface.MLKEY_getPublicKeyBytes(keyId);

            // Free the keypair handle immediately.  This is the critical step:
            // the native address is released here, before any derived PQCKey is
            // constructed, so it cannot alias any derived key's pkeyId.
            nativeInterface.MLKEY_delete(keyId);
            keyId = 0;

            // Return a PQCKey whose pkeyId points to the private-key-only
            // EVP_PKEY* (created from the extracted bytes), and whose public
            // bytes are already populated.  The cleaner for this object will
            // free only that private-key-only pointer.
            String NoDashAlg2 = algName.replace('-', '_');
            long privKeyId = nativeInterface.MLKEY_createPrivateKey(NoDashAlg2, privateKeyBytes);
            System.err.printf("[PQCKey.generateKeyPair] DEBUG: alg=%s MLKEY_createPrivateKey"
                    + " returned privKeyId=0x%x thread=%d%n",
                    algName, privKeyId, Thread.currentThread().getId());
            System.err.flush();
            if (privKeyId == 0) {
                Arrays.fill(privateKeyBytes, (byte) 0);
                throw new NativeException("PQCKey.generateKeyPair: MLKEY_createPrivateKey failed");
            }
            System.err.printf("[PQCKey.generateKeyPair] DEBUG: alg=%s thread=%d"
                    + " privateKeyBytes.len=%d privateKeyBytes=%s%n",
                    algName, Thread.currentThread().getId(),
                    privateKeyBytes.length, toHexFull(privateKeyBytes));
            System.err.printf("[PQCKey.generateKeyPair] DEBUG: alg=%s thread=%d"
                    + " publicKeyBytes.len=%d publicKeyBytes=%s%n",
                    algName, Thread.currentThread().getId(),
                    publicKeyBytes.length, toHexFull(publicKeyBytes));
            System.err.flush();
            PQCKey result = new PQCKey(nativeInterface, privKeyId, privateKeyBytes, publicKeyBytes, algName, provider);
            return result;

        } catch (NativeException e) {
            if (keyId != 0) {
                try { nativeInterface.MLKEY_delete(keyId); } catch (Exception ignored) {}
            }
            throw e;
        } catch (Exception e) {
            if (keyId != 0) {
                try { nativeInterface.MLKEY_delete(keyId); } catch (Exception ignored) {}
            }
            throw new NativeException("PQCKey.generateKeyPair: Exception " + e.getMessage(), e);
        }
    }

    public static PQCKey createPrivateKey(String algName, byte[] privateKeyBytes, OpenJCEPlusProvider provider, String configType)
            throws NativeException {
        // final String methodName = "createPrivateKey ";
        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = NativeCryptoSelector.selectBackend(provider, configType, algName);
        long keyId = 0;
        String NoDashAlg = algName.replace('-', '_');
        System.err.printf("[PQCKey.createPrivateKey] DEBUG: alg=%s configType=%s thread=%d"
                + " privateKeyBytes.len=%d privateKeyBytes=%s%n",
                algName, configType, Thread.currentThread().getId(),
                privateKeyBytes.length, toHexFull(privateKeyBytes));
        System.err.flush();
        keyId = nativeInterface.MLKEY_createPrivateKey(NoDashAlg, privateKeyBytes);
        System.err.printf("[PQCKey.createPrivateKey] DEBUG: alg=%s MLKEY_createPrivateKey"
                + " returned keyId=0x%x thread=%d%n",
                algName, keyId, Thread.currentThread().getId());
        System.err.flush();

        return new PQCKey(nativeInterface, keyId, privateKeyBytes.clone(), (byte[]) null, algName, provider);
    }

    public static PQCKey createPublicKey(String algName, byte[] publicKeyBytes, OpenJCEPlusProvider provider, String configType)
            throws NativeException {
        // final String methodName = "createPublicKey ";
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = NativeCryptoSelector.selectBackend(provider, configType, algName);
        long keyId = 0;
        String NoDashAlg = algName.replace('-', '_');
        // publicKeyBytes is in BIT STRING format: 03 82 xx xx 00 <raw key bytes>.
        // Log the full buffer so the exact bytes passed to MLKEY_createPublicKey are reproducible.
        System.err.printf("[PQCKey.createPublicKey] DEBUG: alg=%s configType=%s thread=%d"
                + " publicKeyBytes.len=%d publicKeyBytes=%s%n",
                algName, configType, Thread.currentThread().getId(),
                publicKeyBytes.length, toHexFull(publicKeyBytes));
        System.err.flush();
        keyId = nativeInterface.MLKEY_createPublicKey(NoDashAlg, publicKeyBytes);
        System.err.printf("[PQCKey.createPublicKey] DEBUG: alg=%s MLKEY_createPublicKey"
                + " returned keyId=0x%x thread=%d%n",
                algName, keyId, Thread.currentThread().getId());
        System.err.flush();

        // OCKDebug.Msg (debPrefix, methodName, "mlkemKeyId :" + mlkemKeyId);
        return new PQCKey(nativeInterface, keyId, null, publicKeyBytes.clone(), algName, provider);
    }

    private PQCKey(NativeInterface nativeInterface, long keyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, String algName, OpenJCEPlusProvider provider) throws NativeException {
        this.nativeInterface = nativeInterface;
        this.pkeyId.setValue(keyId);
        this.algName = algName;
        this.provider = provider;

        if (!validId(keyId)) {
            throw new NativeException(badIdMsg);
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        if (privateKeyBytes == unobtainedKeyBytes) {
            this.privateKeyBytes = this.nativeInterface.MLKEY_getPrivateKeyBytes(keyId);
        } else {
            this.privateKeyBytes = privateKeyBytes;
        }
        if (publicKeyBytes == unobtainedKeyBytes) {
            this.publicKeyBytes = this.nativeInterface.MLKEY_getPublicKeyBytes(keyId);
        } else {
            this.publicKeyBytes = publicKeyBytes;
        }

        System.err.printf("[PQCKey] DEBUG: constructor alg=%s pkeyId=0x%x"
                + " identityHashCode=0x%x thread=%d%n",
                algName, keyId, System.identityHashCode(this),
                Thread.currentThread().getId());
        System.err.flush();

        // The cleaner captures pkeyId (PrimitiveWrapper.Long) by reference and
        // this.privateKeyBytes by reference via the ByteArray wrapper.
        // After MLKEY_delete fires, pkeyId is zeroed so any subsequent
        // getPKeyId() call returns 0 and validId() throws — preventing
        // silent use of a recycled native address.
        PrimitiveWrapper.ByteArray privBytesWrapper = new PrimitiveWrapper.ByteArray(this.privateKeyBytes);
        System.err.printf("[PQCKey] DEBUG: registering cleaner pkeyId=0x%x%n", keyId);
        System.err.flush();

        this.provider.registerCleanable(this, cleanOCKResources(privBytesWrapper, pkeyId, this.nativeInterface));
    }

    @Override
    public String getAlgorithm() {
        return algName;
    }

    @Override
    public long getPKeyId() throws NativeException {
        long id = pkeyId.getValue();
        System.err.printf("[PQCKey] DEBUG: getPKeyId alg=%s pkeyId=0x%x"
                + " identityHashCode=0x%x thread=%d%n",
                algName, id, System.identityHashCode(this),
                Thread.currentThread().getId());
        System.err.flush();
        if (!validId(id)) {
            throw new NativeException(badIdMsg + " (already freed)");
        }
        return id;
    }

    @Override
    public byte[] getPrivateKeyBytes() throws NativeException {
        // final String methodName = "getPrivateKeyBytes :";
        if (privateKeyBytes == unobtainedKeyBytes) {
            obtainPrivateKeyBytes();
        }
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws NativeException {
        // final String methodName = "getPublicKeyBytes";
        if (publicKeyBytes == unobtainedKeyBytes) {
            obtainPublicKeyBytes();
        }
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    private synchronized void obtainPrivateKeyBytes() throws NativeException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (privateKeyBytes == unobtainedKeyBytes) {
            long id = pkeyId.getValue();
            if (!validId(id)) {
                throw new NativeException(badIdMsg);
            }
            System.err.printf("[PQCKey] DEBUG: obtainPrivateKeyBytes pkeyId=0x%x%n", id);
            this.privateKeyBytes = this.nativeInterface.MLKEY_getPrivateKeyBytes(id);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws NativeException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (publicKeyBytes == unobtainedKeyBytes) {
            long id = pkeyId.getValue();
            if (!validId(id)) {
                throw new NativeException(badIdMsg);
            }
            this.publicKeyBytes = this.nativeInterface.MLKEY_getPublicKeyBytes(id);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        // final String methodName = "validId";
        // OCKDebug.Msg(debPrefix, methodName, id);
        return (id != 0L);
    }

    public String toString() {
        String out = "Algorithm Name =  " + this.algName + "\n" +
            "Private Key - " + this.privateKeyBytes + "\n" +
            "Public Key - " + this.publicKeyBytes;
        return out;
    }

    /** Debug helper: hex-encode the entire byte array. */
    private static String toHexFull(byte[] b) {
        if (b == null) return "<null>";
        if (b.length == 0) return "(empty)";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            sb.append(String.format("%02x", v & 0xFF));
        }
        return sb.toString();
    }

    private Runnable cleanOCKResources(PrimitiveWrapper.ByteArray privBytesWrapper,
            PrimitiveWrapper.Long pkeyIdWrapper, NativeInterface nativeInterface) {
        return () -> {
            try {
                long id = pkeyIdWrapper.getValue();
                System.err.printf("[PQCKey] DEBUG: CLEANER FIRED pkeyId=0x%x thread=%d%n",
                        id, Thread.currentThread().getId());
                System.err.flush();

                byte[] privBytes = privBytesWrapper.getValue();
                if (privBytes != null && privBytes != unobtainedKeyBytes) {
                    Arrays.fill(privBytes, (byte) 0x00);
                }
                if (id != 0) {
                    System.err.printf("[PQCKey] DEBUG: CLEANER calling MLKEY_delete pkeyId=0x%x%n", id);
                    System.err.flush();
                    // Zero the wrapper BEFORE freeing so any concurrent getPKeyId()
                    // call sees 0 and throws rather than using the freed address.
                    pkeyIdWrapper.setValue(0);
                    nativeInterface.MLKEY_delete(id);
                }
            } catch (Exception e) {
                System.err.printf("[PQCKey] DEBUG: CLEANER exception: %s%n", e.getMessage());
                System.err.flush();
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
