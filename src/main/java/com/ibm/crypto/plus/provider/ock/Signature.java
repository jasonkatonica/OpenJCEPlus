/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

import java.security.InvalidKeyException;

public final class Signature {

    private OCKContext ockContext = null;
    private Digest digest = null;
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private boolean convertKey = false;
    private final String badIdMsg = "Digest Identifier or PKey Identifier is not valid";
    private final static String debPrefix = "SIGNATURE";

    public static Signature getInstance(OCKContext ockContext, String digestAlgo)
            throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        return new Signature(ockContext, digestAlgo);
    }


    private Signature(OCKContext ockContext, String digestAlgo) throws OCKException {
        //final String methodName = "Signature(String)";
        this.ockContext = ockContext;
        this.digest = Digest.getInstance(ockContext, digestAlgo);
        //OCKDebug.Msg (debPrefix, methodName, "digestAlgo :" + digestAlgo);
    }

    public void update(byte[] input, int offset, int length) throws OCKException {
        if ((input == null) || (length < 0) || (offset < 0) || ((offset + length) > input.length)) {
            throw new IllegalArgumentException("Bad input parameters to Signature update");
        }

        this.digest.update(input, offset, length);
    }

    public void initialize(AsymmetricKey key, boolean rsaPlain)
            throws InvalidKeyException, OCKException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        // Do necessary clean up before doing this. Just in case the object is reused.
        this.digest.reset();

        this.key = key;
        this.initialized = true;
        this.convertKey = rsaPlain;
        //OCKDebug.Msg (debPrefix, methodName,  "this.key=" + key);
    }

    public synchronized byte[] sign() throws OCKException {

        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        //OCKDebug.Msg (debPrefix, "sign", "digestId :" + digest.getId() + " pkeyId :" + this.key.getPKeyId());
        if ((this.digest == null) || !validId(this.digest.getId())
                || !validId(this.key.getPKeyId())) {
            throw new OCKException(badIdMsg);
        }

        byte[] signature = null;
        try {
            System.out.println("this.ockContext.getId(): " + this.ockContext.getId());
            System.out.println("digest.getId(): " + digest.getId());
            System.out.println("this.key.getPKeyId(): " + this.key.getPKeyId());
            System.out.println("this.key.getPrivateKeyBytes(): " + toHexString(this.key.getPrivateKeyBytes()));
            System.out.println("this.key.getPublicKeyBytes(): " + toHexString(this.key.getPublicKeyBytes()));
            System.out.println("this.key.getAlgorithm(): " + this.key.getAlgorithm());
            System.out.println("this.convertKey: " + this.convertKey);
            signature = NativeInterface.SIGNATURE_sign(this.ockContext.getId(), digest.getId(),
                    this.key.getPKeyId(), this.convertKey);
        } finally {
            // Try to reset even if OCKException is thrown
            this.digest.reset();
        }

        //OCKDebug.Msg (debPrefix, "sign",  "signature :" + signature);
        return signature;
    }

    public synchronized boolean verify(byte[] sigBytes) throws OCKException {
        //final String methodName = "verify";
        // create key length function and check sigbytes against key length?
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (sigBytes == null) {
            throw new IllegalArgumentException("invalid signature");
        }
        //OCKDebug.Msg (debPrefix, methodName,  "digestId :" + digest.getId() + " pkeyId :" + this.key.getPKeyId());
        //OCKDebug.Msg (debPrefix, methodName,  " sigBytes :",  sigBytes);
        if ((this.digest == null) || digest.getId() == 0L || this.key.getPKeyId() == 0L) {
            throw new OCKException(badIdMsg);
        }

        boolean verified = false;
        try {
            verified = NativeInterface.SIGNATURE_verify(this.ockContext.getId(), digest.getId(),
                    this.key.getPKeyId(), sigBytes);
        } finally {
            // Try to reset even if OCKException is thrown
            this.digest.reset();
        }

        //        if (!verified) {
        //            OCKDebug.Msg (debPrefix, methodName,  "Failed to verify Signature."); 
        //        }

        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {

        //OCKDebug.Msg (debPrefix, "validId", "id :" + id);
        return (id != 0L);
    }

    /** * Converts a byte array to hex string */
    private static String toHexString(byte[] block) {
        if (block == null) {
            return "Hex String is NULL";
        }

        StringBuffer buf = new StringBuffer();
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                'E', 'F'};
        int len = block.length;
        int high = 0;
        int low = 0;
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0)
                buf.append('\n');
            high = ((block[i] & 0xf0) >> 4);
            low = (block[i] & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
            buf.append(' ');
        }
        buf.append('\n');
        return buf.toString();
    }
}
