/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.util.Arrays;

public final class PQCKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final long pkeyId;
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
            if (privKeyId == 0) {
                Arrays.fill(privateKeyBytes, (byte) 0);
                throw new NativeException("PQCKey.generateKeyPair: MLKEY_createPrivateKey failed");
            }
            return new PQCKey(nativeInterface, privKeyId, privateKeyBytes, publicKeyBytes, algName, provider);

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
        keyId = nativeInterface.MLKEY_createPrivateKey(NoDashAlg, privateKeyBytes);

        return new PQCKey(nativeInterface, keyId, privateKeyBytes.clone(), null, algName, provider);
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
        keyId = nativeInterface.MLKEY_createPublicKey(NoDashAlg, publicKeyBytes);

        // OCKDebug.Msg (debPrefix, methodName, "mlkemKeyId :" + mlkemKeyId);
        return new PQCKey(nativeInterface, keyId, null, publicKeyBytes.clone(), algName, provider);
    }

    private PQCKey(NativeInterface nativeInterface, long keyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, String algName, OpenJCEPlusProvider provider) throws NativeException {
        this.nativeInterface = nativeInterface;
        this.pkeyId = keyId;
        this.algName = algName;
        this.provider = provider;

        if (!validId(pkeyId)) {
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
                + " identityHashCode=0x%x thread=%d"
                + " privateKeyBytes_param_is_unobtained=%b%n",
                algName, keyId, System.identityHashCode(this),
                Thread.currentThread().getId(),
                (privateKeyBytes == unobtainedKeyBytes));
        // IMPORTANT: the lambda captures the 'privateKeyBytes' *parameter* reference,
        // not 'this.privateKeyBytes'.  When called from generateKeyPair() the parameter
        // is the sentinel 'unobtainedKeyBytes'.  If the cleaner fires before the key
        // is used, it will NOT zero 'this.privateKeyBytes' (which holds the real
        // material).  More critically, if the pkeyId is freed by the cleaner of a
        // *different* PQCKey object that happens to have the same numeric id (e.g. due
        // to allocator reuse) the decapsulation will silently produce the wrong secret.
        // Log both references so the mismatch is visible.
        System.err.printf("[PQCKey] DEBUG: registering cleaner pkeyId=0x%x"
                + " cleaner_param_ref=%s this.privateKeyBytes_ref=%s%n",
                keyId,
                (privateKeyBytes == null ? "null"
                        : (privateKeyBytes == unobtainedKeyBytes ? "unobtainedKeyBytes"
                                : "user-supplied")),
                (this.privateKeyBytes == null ? "null"
                        : (this.privateKeyBytes == unobtainedKeyBytes ? "unobtainedKeyBytes"
                                : "resolved[" + this.privateKeyBytes.length + "]")));
        System.err.flush();

        this.provider.registerCleanable(this, cleanOCKResources(privateKeyBytes, pkeyId, this.nativeInterface));
    }

    @Override
    public String getAlgorithm() {
        return algName;
    }

    @Override
    public long getPKeyId() throws NativeException {
        System.err.printf("[PQCKey] DEBUG: getPKeyId alg=%s pkeyId=0x%x"
                + " identityHashCode=0x%x thread=%d%n",
                algName, pkeyId, System.identityHashCode(this),
                Thread.currentThread().getId());
        System.err.flush();
        return pkeyId;
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
            if (!validId(pkeyId)) {
                throw new NativeException(badIdMsg);
            }
        
            System.out.println("getPrivKeyBytes - pkeyId :" + pkeyId);
            this.privateKeyBytes = this.nativeInterface.MLKEY_getPrivateKeyBytes(pkeyId);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws NativeException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (publicKeyBytes == unobtainedKeyBytes) {
            if (!validId(pkeyId)) {
                throw new NativeException(badIdMsg);
            }
            this.publicKeyBytes = this.nativeInterface.MLKEY_getPublicKeyBytes(pkeyId);
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

    private Runnable cleanOCKResources(byte[] privateKeyBytes, long pkeyId, NativeInterface nativeInterface) {
        return () -> {
            try {
                System.err.printf("[PQCKey] DEBUG: CLEANER FIRED pkeyId=0x%x"
                        + " thread=%d"
                        + " privateKeyBytes_captured_ref=%s%n",
                        pkeyId,
                        Thread.currentThread().getId(),
                        (privateKeyBytes == null ? "null"
                                : (privateKeyBytes == unobtainedKeyBytes ? "unobtainedKeyBytes"
                                        : "user-supplied[" + privateKeyBytes.length + "]")));
                System.err.flush();

                if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                    Arrays.fill(privateKeyBytes, (byte) 0x00);
                }
                if (pkeyId != 0) {
                    System.err.printf("[PQCKey] DEBUG: CLEANER calling MLKEY_delete pkeyId=0x%x%n",
                            pkeyId);
                    System.err.flush();
                    nativeInterface.MLKEY_delete(pkeyId);
                }
            } catch (Exception e) {
                System.err.printf("[PQCKey] DEBUG: CLEANER exception for pkeyId=0x%x: %s%n",
                        pkeyId, e.getMessage());
                System.err.flush();
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
