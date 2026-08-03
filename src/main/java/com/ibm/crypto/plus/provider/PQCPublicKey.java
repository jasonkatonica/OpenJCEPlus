/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.PQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;



@SuppressWarnings("restriction")
final class PQCPublicKey extends X509Key
        implements Destroyable {



    private static final long serialVersionUID = -7291096793479000585L;

    private OpenJCEPlusProvider provider = null;
    private String name;

    private transient boolean destroyed = false;
    private transient PQCKey pqcKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    PQCPublicKey(OpenJCEPlusProvider provider, byte[] rawKey, String algName)
            throws InvalidKeyException {
        System.out.println("[DBG PQCPublicKey ctor-1] alg=" + algName
                + " rawKey.length=" + rawKey.length
                + " rawKey[0..4]=" + hex(Arrays.copyOf(rawKey, Math.min(5, rawKey.length))));
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.provider = provider;
        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

        setKey(new BitArray(rawKey.length * 8, rawKey));
        try {
            // OCKC needs the key with a BitArray encoding to process it as raw.
            DerOutputStream tmp = new DerOutputStream();
            tmp.putUnalignedBitString(getKey());
            byte[] b = tmp.toByteArray();
            tmp.close();

            System.out.println("[DBG PQCPublicKey ctor-1] bytes-to-OCK.length=" + b.length
                    + " bytes-to-OCK[0..7]=" + hex(Arrays.copyOf(b, Math.min(8, b.length))));
            this.pqcKey = PQCKey.createPublicKey(algName, b, provider, "KeyFactory");
            System.out.println("[DBG PQCPublicKey ctor-1] pqcKey.pkeyId=" + this.pqcKey.getPKeyId());
        } catch (Exception exception) {
            throw new InvalidKeyException("Failed to create public key", exception);
        }
    }

    PQCPublicKey(OpenJCEPlusProvider provider, PQCKey pqcKey) {
        try {
            this.provider = provider;
            byte[] rawKey = pqcKey.getPublicKeyBytes();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(pqcKey.getAlgorithm()));

            this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

            System.out.println("[DBG PQCPublicKey ctor-2] alg=" + this.name
                    + " rawKey.length=" + rawKey.length
                    + " rawKey[0..7]=" + hex(Arrays.copyOf(rawKey, Math.min(8, rawKey.length))));

            //OCKC puts the BITSTRING on the key. Need to remove it.
            // rawKey is: 03 82 xx xx 00 <actual-key-bytes>
            // That is: tag(1) + 2-byte-long-form-len(3) + unused-bits-byte(1) = 5 header bytes
            byte tag         = rawKey[0];
            byte lenForm     = rawKey[1];
            int  declaredLen = ((rawKey[2] & 0xFF) << 8) | (rawKey[3] & 0xFF);
            byte unusedBits  = rawKey[4];
            int  payloadLen  = rawKey.length - 5;

            System.out.println("[DBG PQCPublicKey ctor-2] BIT STRING header:"
                    + " tag=0x" + String.format("%02x", tag)
                    + " lenForm=0x" + String.format("%02x", lenForm)
                    + " declaredLen=" + declaredLen
                    + " unusedBits=" + unusedBits
                    + " payloadLen=" + payloadLen
                    + " (rawKey.length-5)=" + (rawKey.length - 5));

            if (unusedBits != 0) {
                System.out.println("[DBG PQCPublicKey ctor-2] WARNING: unusedBits=" + unusedBits
                        + " is non-zero; key bytes may be misaligned!");
            }
            if (declaredLen != rawKey.length - 4) {
                System.out.println("[DBG PQCPublicKey ctor-2] WARNING: declaredLen=" + declaredLen
                        + " does not match rawKey.length-4=" + (rawKey.length - 4)
                        + "; header parse may be wrong!");
            }

            // OCK wraps the key in a DER BIT STRING but the unusedBits byte (rawKey[4])
            // is sometimes non-zero even though ML-KEM keys are always byte-aligned.
            // Ignoring unusedBits and copying the payload bytes directly produces the
            // correct, canonical key value that round-trips cleanly through getEncoded().
            byte[] keyPayload = Arrays.copyOfRange(rawKey, 5, rawKey.length);
            setKey(new BitArray(keyPayload.length * 8, keyPayload));

            byte[] storedKeyBytes = getKey().toByteArray();
            System.out.println("[DBG PQCPublicKey ctor-2] storedKey.length=" + storedKeyBytes.length
                    + " storedKey[0..3]=" + hex(Arrays.copyOf(storedKeyBytes, Math.min(4, storedKeyBytes.length))));

            this.pqcKey = pqcKey;
        } catch (Exception exception) {
            throw provider.providerException("Failure in PublicKey + " + exception.getMessage(), exception);
        }
    }

    PQCPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        System.out.println("[DBG PQCPublicKey ctor-3] encoded.length=" + encoded.length
                + " encoded[0..4]=" + hex(Arrays.copyOf(encoded, Math.min(5, encoded.length))));
        this.provider = provider;

        try {
            decode(encoded);

            this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

            byte[] keyBits = getKey().toByteArray();
            System.out.println("[DBG PQCPublicKey ctor-3] alg=" + this.name
                    + " getKey().length=" + keyBits.length
                    + " getKey()[0..3]=" + hex(Arrays.copyOf(keyBits, Math.min(4, keyBits.length))));

            DerOutputStream tmp = new DerOutputStream();
            tmp.putUnalignedBitString(getKey());
            byte[] b = tmp.toByteArray();
            tmp.close();

            System.out.println("[DBG PQCPublicKey ctor-3] bytes-to-OCK.length=" + b.length
                    + " bytes-to-OCK[0..7]=" + hex(Arrays.copyOf(b, Math.min(8, b.length))));
            this.pqcKey = PQCKey.createPublicKey(name, b, provider, "KeyFactory");
            System.out.println("[DBG PQCPublicKey ctor-3] pqcKey.pkeyId=" + this.pqcKey.getPKeyId());
        } catch (Exception e) {
            throw new InvalidKeyException("Failure in PublicKey -" + e.getMessage(), e);
        }
    }

    /**
     * Returns the name of the algorithm associated with this key
     */
    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
    }

    /**
     * Returns the encoding format of this key: "X.509"
     */
    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        byte[] encodedKey = null;
        try {
            byte[] keyBits = getKey().toByteArray();
            System.out.println("[DBG PQCPublicKey getEncoded] alg=" + this.name
                    + " getKey().length=" + keyBits.length
                    + " getKey()[0..3]=" + hex(Arrays.copyOf(keyBits, Math.min(4, keyBits.length))));

            DerOutputStream out = new DerOutputStream();
            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream bytes = new DerOutputStream();
            bytes.putOID(algid.getOID());
            tmp.write(DerValue.tag_Sequence, bytes);
            tmp.putUnalignedBitString(getKey());
            out.write(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            out.close();
            tmp.close();
            bytes.close();

            System.out.println("[DBG PQCPublicKey getEncoded] encodedKey.length=" + encodedKey.length
                    + " encodedKey[0..4]=" + hex(Arrays.copyOf(encodedKey, Math.min(5, encodedKey.length))));
        } catch (IOException ex) {
            return encodedKey;
        }
        return encodedKey;
    }

    // Debug helper — hex-encodes a byte array.
    private static String hex(byte[] b) {
        if (b == null) return "<null>";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }

    PQCKey getPQCKey() {
        return this.pqcKey;
    }

    private Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    }
    
    /**
     * Destroys this key. A call to any of its other methods after this will cause
     * an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            setKey(new BitArray(0));
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }
}
