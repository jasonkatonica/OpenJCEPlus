/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.PrimitiveWrapper;
import com.ibm.crypto.plus.provider.SystemAccessUtils;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class Digest implements Cloneable {

    /* ===========================================================================
       Digest caching mechanism
       Cache native digest contexts so that the same contexts could be reused later after resetting.
       */

    // index corresponding the digest algorithm it's using
    // also used as a flag:
    // >= 0: it is using one of the cached algorithms
    // -1  : Not initialized
    // -2  : Not a cached digest algorithm
    private int algIndx = -1;

    private PrimitiveWrapper.Bool needsReinit = new PrimitiveWrapper.Bool(false);

    private boolean contextFromQueue = false;

    // Size of {SHA256, SHA384, SHA512, SHA224, SHA1, MD5, SHA512-224, SHA512-256, SHA3-224, SHA3-256, SHA3-384, SHA3-512}
    final static int[] digestLengths = {32, 48, 64, 28, 20, 16, 28, 32, 28, 32, 48, 64};

    //disable caching mechanism for windows OS
    final static private boolean isWindows = SystemAccessUtils.getSystemProperty("os.name").startsWith("Windows");

    final static private int numContexts;

    final static int numDigestAlgos = 12;
    private static final String DIGEST_CONTEXT_CACHE_SIZE = "com.ibm.crypto.provider.DigestContextCacheSize";

    private static final Map<NativeInterface, ConcurrentLinkedQueueLong[]> contextsPerBackend = new HashMap<>();

    private static final Map<NativeInterface, Integer[]> runtimeContextNumPerBackend = new HashMap<>();

    class ConcurrentLinkedQueueLong extends ConcurrentLinkedQueue<Long> {
        private static final long serialVersionUID = 196745693267521676L;
    }

    static {
        // Configurable number of cached contexts
        int num;
        if (isWindows) {
            num = 0;
        } else {
            try {
                num = Integer.parseInt(SystemAccessUtils.getSystemProperty(
                        DIGEST_CONTEXT_CACHE_SIZE, "2048"));
            } catch (NumberFormatException e) {
                num = 0;
            }
        }
        numContexts = num;
    }

    void getContext() throws NativeException {
        ConcurrentLinkedQueueLong[] contexts = contextsPerBackend.get(this.nativeInterface);
        Integer[] runtimeContextNum = runtimeContextNumPerBackend.get(this.nativeInterface);
        if ((contexts == null) || (runtimeContextNum == null)) {
            synchronized (Digest.class) {
                contexts = contextsPerBackend.get(this.nativeInterface);
                runtimeContextNum = runtimeContextNumPerBackend.get(this.nativeInterface);
                if ((contexts == null) || (runtimeContextNum == null)) {
                    contexts = new ConcurrentLinkedQueueLong[numDigestAlgos];
                    runtimeContextNum = new Integer[numDigestAlgos];

                    for (int i = 0; i < numDigestAlgos; i++) {
                        contexts[i] = new ConcurrentLinkedQueueLong();
                        runtimeContextNum[i] = 0;
                    }
                    contextsPerBackend.put(this.nativeInterface, contexts);
                    runtimeContextNumPerBackend.put(this.nativeInterface, runtimeContextNum);
                }
            }
        }

        if (this.digestId != 0) {
            return;
        }

        if (this.algIndx == -1) {
            switch (this.digestAlgo) {
                case "SHA256":
                    this.algIndx = 0;
                    break;
                case "SHA384":
                    this.algIndx = 1;
                    break;
                case "SHA512":
                    this.algIndx = 2;
                    break;
                case "SHA224":
                    this.algIndx = 3;
                    break;
                case "SHA1":
                    this.algIndx = 4;
                    break;
                case "MD5":
                    this.algIndx = 5;
                    break;
                case "SHA512-224":
                    this.algIndx = 6;
                    break;
                case "SHA512-256":
                    this.algIndx = 7;
                    break;
                case "SHA3-224":
                    this.algIndx = 8;
                    break;
                case "SHA3-256":
                    this.algIndx = 9;
                    break;
                case "SHA3-384":
                    this.algIndx = 10;
                    break;
                case "SHA3-512":
                    this.algIndx = 11;
                    break;
                default:
                    this.algIndx = -2;
                    break;
            }
        }

        // Algorithm is not in cached list
        if (this.algIndx == -2) {
            this.digestId = this.nativeInterface.DIGEST_create(this.digestAlgo);
        } else {
            Long context = contexts[this.algIndx].poll();

            if (context == null) {
                // Create new context
                this.digestId = this.nativeInterface
                        .DIGEST_create(this.digestAlgo);
                this.contextFromQueue = (runtimeContextNum[this.algIndx] < numContexts);
                if (runtimeContextNum[this.algIndx] < numContexts) {
                    runtimeContextNum[this.algIndx]++;
                }
            } else {
                this.digestId = context;
                this.contextFromQueue = true;
            }
        }
        this.needsReinit.setValue(false);
    }

    /* end digest caching mechanism
     * ===========================================================================
     */

    // Optimization: small inputs are buffered in Java (copied, so later changes by the
    // caller to its array cannot affect the result) and handed to the native layer
    // together with the final digest in ONE JNI call (update + final + reset). This
    // removes one JNI crossing for the common update(small) + digest() sequence.
    // Larger inputs go directly to native (no extra copy) as before.
    private static final int PENDING_MAX = 256;
    private byte[] pending = null;
    private int pendingLen = 0;

    private int digestLength = 0;
    private final String badIdMsg = "Digest Identifier is not valid";
    private static final String debPrefix = "DIGEST";

    private String digestAlgo;
    private String configType = "MessageDigest";

    private long digestId = 0;

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;

    public static Digest getInstance(String digestAlgo, OpenJCEPlusProvider provider, String configType, String configAlgName) throws NativeException {
        if (digestAlgo == null || digestAlgo.isEmpty()) {
            throw new IllegalArgumentException("digestAlgo is null/empty");
        }

        return new Digest(digestAlgo, provider, configType, configAlgName);
    }

    public static Digest getInstance(String digestAlgo, OpenJCEPlusProvider provider, String configAlgName) throws NativeException {
        if (digestAlgo == null || digestAlgo.isEmpty()) {
            throw new IllegalArgumentException("digestAlgo is null/empty");
        }

        return new Digest(digestAlgo, provider, configAlgName);
    }

    private Digest(String digestAlgo, OpenJCEPlusProvider provider, String configType, String configAlgName) throws NativeException {
        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null.");
        }

        this.configType = configType;
        this.digestAlgo = digestAlgo;
        this.provider = provider;
        this.nativeInterface = NativeCryptoSelector.selectBackend(provider, configType, configAlgName);
        getContext();
        if (this.algIndx >= 0 && this.algIndx < numDigestAlgos) {
            this.digestLength = digestLengths[this.algIndx];
        }
        //OCKDebug.Msg(debPrefix, methodName,  "digestAlgo :" + digestAlgo);

        this.provider.registerCleanable(this, cleanOCKResources(digestId, algIndx,
            contextFromQueue, needsReinit, nativeInterface));
    }

    private Digest(String digestAlgo, OpenJCEPlusProvider provider, String configAlgname) throws NativeException {
        //final String methodName = "Digest(String)";
        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null.");
        }

        this.digestAlgo = digestAlgo;
        this.provider = provider;
        this.nativeInterface = NativeCryptoSelector.selectBackend(provider, configType, configAlgname);
        getContext();
        if (this.algIndx >= 0 && this.algIndx < numDigestAlgos) {
            this.digestLength = digestLengths[this.algIndx];
        }
        //OCKDebug.Msg(debPrefix, methodName,  "digestAlgo :" + digestAlgo);

        this.provider.registerCleanable(this, cleanOCKResources(digestId, algIndx,
            contextFromQueue, needsReinit, nativeInterface));
    }

    private Digest() {
    }

    static void throwNativeException(int errorCode) throws NativeException {
        //final String methodName = "throwOCKExeption";
        // OCKDebug.Msg(debPrefix, methodName, "throwNativeException errorCode =  " + errorCode);
        switch (errorCode) {
            case -1:
                throw new NativeException("ICC_EVP_DigestFinal failed!");
            case -2:
                throw new NativeException("ICC_EVP_DigestInit failed!");
            case -3:
                throw new NativeException("ICC_EVP_DigestUpdate failed!");
            default:
                throw new NativeException("Unknow Error Code");
        }
    }

    // Optimization: MessageDigest is not thread-safe per JCA specification.
    // Removing synchronized avoids monitor enter/exit instructions and memory barriers on the hot path.
    public void update(byte[] input, int offset, int length) throws NativeException {
        if (length == 0) {
            return;
        }

        if (input == null || offset < 0 || length < 0 || offset > input.length - length) {
            throw new IllegalArgumentException("Input range is invalid.");
        }

        if (this.digestId == 0) {
            throw new NativeException(badIdMsg);
        }

        if (length <= PENDING_MAX - this.pendingLen) {
            // Buffer small input; it is sent to native with the next digest()/flush.
            if (this.pending == null) {
                this.pending = new byte[PENDING_MAX];
            }
            System.arraycopy(input, offset, this.pending, this.pendingLen, length);
            this.pendingLen += length;
            return;
        }

        flushPending();

        if (length <= PENDING_MAX) {
            if (this.pending == null) {
                this.pending = new byte[PENDING_MAX];
            }
            System.arraycopy(input, offset, this.pending, 0, length);
            this.pendingLen = length;
            return;
        }

        int errorCode = this.nativeInterface.DIGEST_update(this.digestId, input, offset, length);
        if (errorCode < 0) {
            throwNativeException(errorCode);
        }
        this.needsReinit.setValue(true);
    }

    // Sends any buffered input to the native context. Must be called before anything
    // else touches the native context (clone, PKCS12 helper, getId() users).
    private void flushPending() throws NativeException {
        int len = this.pendingLen;
        if (len == 0) {
            return;
        }
        this.pendingLen = 0;
        byte[] buf = this.pending;
        int errorCode;
        try {
            errorCode = this.nativeInterface.DIGEST_update(this.digestId, buf, 0, len);
        } finally {
            Arrays.fill(buf, 0, len, (byte) 0);
        }
        if (errorCode < 0) {
            throwNativeException(errorCode);
        }
        this.needsReinit.setValue(true);
    }

    // Final digest into 'out' (exactly digest length), merging buffered input, if any,
    // into the same JNI call. Resets the native context.
    private void digestInto(byte[] out) throws NativeException {
        int len = this.pendingLen;
        int errorCode;
        if (len == 0) {
            errorCode = this.nativeInterface.DIGEST_digest_and_reset(this.digestId, out);
        } else {
            this.pendingLen = 0;
            byte[] buf = this.pending;
            try {
                errorCode = this.nativeInterface.DIGEST_updateDigestAndReset(this.digestId, buf, 0, len, out);
            } finally {
                Arrays.fill(buf, 0, len, (byte) 0);
            }
        }
        if (errorCode < 0) {
            throwNativeException(errorCode);
        }
        this.needsReinit.setValue(false);
    }

    // Optimization: MessageDigest is not thread-safe per JCA specification.
    // Removing synchronized avoids monitor enter/exit instructions and memory barriers on the hot path.
    public byte[] digest() throws NativeException {
        if (this.digestId == 0) {
            throw new NativeException(badIdMsg);
        }

        int len = (this.digestLength != 0) ? this.digestLength : getDigestLength();
        byte[] digestBytes = new byte[len];

        digestInto(digestBytes);

        return digestBytes;
    }

    // Optimization: Allow direct output into caller-provided buffer to avoid temporary array allocation.
    public int digest(byte[] buf, int offset, int len) throws NativeException {
        if (this.digestId == 0) {
            throw new NativeException(badIdMsg);
        }

        int dLen = (this.digestLength != 0) ? this.digestLength : getDigestLength();
        if (offset == 0 && buf.length == dLen) {
            digestInto(buf);
        } else {
            byte[] digestBytes = new byte[dLen];
            digestInto(digestBytes);
            System.arraycopy(digestBytes, 0, buf, offset, dLen);
        }

        return dLen;
    }

    protected long getId() throws NativeException {
        //final String methodName = "getId()";
        //OCKDebug.Msg(debPrefix, methodName, "digestId :" + this.digestId);
        // Callers use the native context directly, so it must hold all input.
        if (this.digestId != 0) {
            flushPending();
        }
        return this.digestId;
    }

    public int getDigestLength() throws NativeException {
        //final String methodName = "getDigestLength()";

        if (digestLength == 0) {
            obtainDigestLength();
        }
        //OCKDebug.Msg(debPrefix, methodName, "digestLength :" + digestLength);
        return digestLength;
    }

    // Optimization: MessageDigest is not thread-safe per JCA specification.
    // Removing synchronized avoids monitor enter/exit instructions and memory barriers on the hot path.
    public void reset() throws NativeException {
        //final String methodName = "reset ";
        //OCKDebug.Msg(debPrefix, methodName,  "digestId =" + this.digestId);

        if (this.digestId == 0) {
            return;
        }

        if (!validId(this.digestId)) {
            throw new NativeException(badIdMsg);
        }
        // Buffered input was never sent to native, simply discard (and zeroise) it.
        if (this.pendingLen != 0) {
            Arrays.fill(this.pending, 0, this.pendingLen, (byte) 0);
            this.pendingLen = 0;
        }
        if (this.needsReinit.getValue()) {
            this.nativeInterface.DIGEST_reset(this.digestId);
        }
        this.needsReinit.setValue(false);
    }

    private synchronized void obtainDigestLength() throws NativeException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getDigestLength at the same time, we only want to call the
        // native code one time.

        if (this.algIndx >= 0 && this.algIndx < numDigestAlgos) {
            this.digestLength = digestLengths[this.algIndx];
        } else {
            if (this.digestLength == 0) {
                if (!validId(this.digestId)) {
                    throw new NativeException(badIdMsg);
                }
                this.digestLength = this.nativeInterface.DIGEST_size(this.digestId);
            }
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg(debPrefix, methodName,  "Id : " + id);
        return (id != 0L);
    }

    /**
     * Clones a given Digest.
     */
    public synchronized Object clone() throws CloneNotSupportedException {
        // Create new Digest instance and copy all relevant fields into the copy.
        // Clones do not make use of the cache so always set the value of
        // contextFromQueue to false to ensure that the context is later freed
        // correctly.
        try {
            flushPending();
        } catch (NativeException e) {
            throw new CloneNotSupportedException(e.getMessage());
        }
        Digest copy = new Digest();
        copy.digestLength = this.digestLength;
        copy.algIndx = this.algIndx;
        copy.digestAlgo = new String(this.digestAlgo);
        copy.needsReinit.setValue(this.needsReinit.getValue());
        copy.contextFromQueue = false;
        copy.provider = this.provider;
        copy.nativeInterface = this.nativeInterface;

        // Allocate a new context for the digestId and copy all state information from our
        // original context into the copy.
        try {
            copy.digestId = this.nativeInterface.DIGEST_copy(getId());
            if (0 == copy.digestId) {
                throw new CloneNotSupportedException("Copy of native digest context failed.");
            }
        } catch (NativeException e) {
            StackTraceElement[] stackTraceArray = e.getStackTrace();
            String stackTrace = Stream.of(stackTraceArray)
                                      .map(t -> t.toString())
                                      .collect(Collectors.joining("\n"));
            throw new CloneNotSupportedException(stackTrace);
        }

        this.provider.registerCleanable(copy, cleanOCKResources(copy.digestId, copy.algIndx,
            copy.contextFromQueue, copy.needsReinit, copy.nativeInterface));
        return copy;
    }

    public byte[] PKCS12KeyDeriveHelp(byte[] input, int offset, int length, int iterationCount) throws NativeException {
        int errorCode = 0;

        if (length == 0) {
            return null;
        }

        if (input == null || length < 0 || offset < 0 || (offset + length) > input.length) {
            throw new IllegalArgumentException("Input range is invalid.");
        }

        if (!validId(this.digestId)) {
            throw new NativeException(badIdMsg);
        }

        flushPending();

        errorCode = this.nativeInterface.DIGEST_PKCS12KeyDeriveHelp(this.digestId, input, offset, length, iterationCount);
        if (errorCode < 0) {
            throwNativeException(errorCode);
        }
        this.needsReinit.setValue(false);

        return input;
    }

    private Runnable cleanOCKResources(long digestId, int algIndx, boolean contextFromQueue,
            PrimitiveWrapper.Bool needsReinit, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (digestId == 0) {
                    throw new NativeException("Digest Identifier is not valid");
                }
                // not SHA* algorithm
                if (algIndx == -2) {
                    if (validId(digestId)) {
                        nativeInterface.DIGEST_delete(digestId);
                    }
                } else {
                    if (contextFromQueue) {
                        // reset now to make sure all contexts in the queue are ready to use
                        if (needsReinit.getValue()) {
                            nativeInterface.DIGEST_reset(digestId);
                        }
                        Digest.contextsPerBackend.get(nativeInterface)[algIndx].add(digestId);
                    } else {
                        nativeInterface.DIGEST_delete(digestId);
                    }
                }
            } catch (NativeException e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
