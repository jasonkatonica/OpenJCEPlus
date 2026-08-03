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

            // OCK wraps the public key in a DER BIT STRING:
            //   03 82 <hi> <lo> <unusedBits> <payload>
            // All ML-KEM key sizes (800, 1184, 1568 bytes) use the 2-byte long form (0x82),
            // so the BIT STRING header is always 5 bytes: tag(1)+0x82(1)+hi(1)+lo(1)+ub(1).
            //
            // OCK's ICC_i2d_PublicKey sometimes returns a non-zero unusedBits byte even
            // though ML-KEM keys are always byte-aligned.  When unusedBits != 0, the low
            // unusedBits bits of the last payload byte are garbage and must be masked to
            // zero before storing, so that getEncoded() exports a correct SPKI.
            int unusedBits = rawKey[4] & 0xFF;
            byte[] keyPayload = Arrays.copyOfRange(rawKey, 5, rawKey.length);
            if (unusedBits != 0 && keyPayload.length > 0) {
                // Zero the low unusedBits bits of the last byte (DER masking).
                keyPayload[keyPayload.length - 1] &= (byte)(0xFF << unusedBits);
                System.out.println("[DBG PQCPublicKey ctor-2] FIX: unusedBits=" + unusedBits
                        + " — masked last payload byte: "
                        + String.format("%02x", keyPayload[keyPayload.length - 1] & 0xff));
            }
            setKey(new BitArray(keyPayload.length * 8, keyPayload));

            byte[] storedKeyBytes = getKey().toByteArray();
            System.out.println("[DBG PQCPublicKey ctor-2] storedKey.length=" + storedKeyBytes.length
                    + " storedKey[0..3]=" + hex(Arrays.copyOf(storedKeyBytes, Math.min(4, storedKeyBytes.length))));

            // The pqcKey handle IS the OCK keypair handle from generateKeyPair().
            // We store it directly — no re-import via createPublicKey() needed.
            this.pqcKey = pqcKey;
            System.out.println("[DBG PQCPublicKey ctor-2] pqcKey.pkeyId=" + this.pqcKey.getPKeyId());
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

            // PROBE-A: bit-length of BitArray as stored by X509Key.decode().
            // X509Key.decode() calls getUnalignedBitString() which subtracts unusedBits
            // from the bit-count, so a non-zero unusedBits in the incoming SPKI produces
            // bitLen % 8 != 0.
            int rawBitLen = getKey().length();
            byte[] rawBytes = getKey().toByteArray();
            System.out.println("[DBG PQCPublicKey ctor-3] PROBE-A after decode:"
                    + " alg=" + this.name
                    + " bitLen=" + rawBitLen + " (bitLen%8=" + (rawBitLen % 8) + ")"
                    + " toByteArray().length=" + rawBytes.length
                    + " payload[0..7]=" + hex(Arrays.copyOf(rawBytes, Math.min(8, rawBytes.length))));

            // FIX: if the incoming BIT STRING had a non-zero unusedBits field the
            // BitArray is not byte-aligned.  Re-wrap the already-masked bytes into a
            // fresh byte-aligned BitArray so putUnalignedBitString always emits
            // unusedBits=0 to OCK.
            if (rawBitLen % 8 != 0) {
                int incomingUnusedBits = 8 - (rawBitLen % 8);
                System.out.println("[DBG PQCPublicKey ctor-3] FIX: incoming unusedBits="
                        + incomingUnusedBits
                        + " — normalising BitArray to byte-aligned (last byte already masked by BitArray ctor)");
                // rawBytes from toByteArray() already has the low unusedBits bits zeroed.
                setKey(new BitArray(rawBytes.length * 8, rawBytes));
            }

            // Build the BIT STRING to send to OCK (unusedBits=0 after normalisation above).
            DerOutputStream tmp = new DerOutputStream();
            tmp.putUnalignedBitString(getKey());
            byte[] b = tmp.toByteArray();
            tmp.close();

            // PROBE-B: unusedBits byte that will actually be sent to OCK.
            int hdrLen = ((b[1] & 0xff) == 0x82) ? 4 : ((b[1] & 0xff) == 0x81) ? 3 : 2;
            byte ockUB = (b.length > hdrLen) ? b[hdrLen] : (byte) 0xff;
            System.out.println("[DBG PQCPublicKey ctor-3] PROBE-B bytes-to-OCK:"
                    + " totalLen=" + b.length
                    + " alg=" + this.name
                    + " unusedBits-to-OCK=" + (ockUB & 0xff)
                    + " payload[0..7]=" + hex(Arrays.copyOfRange(b, hdrLen + 1, Math.min(b.length, hdrLen + 9))));
            if (ockUB != 0) {
                System.out.println("[DBG PQCPublicKey ctor-3] *** PROBE-B WARNING: non-zero unusedBits="
                        + (ockUB & 0xff) + " will be sent to OCK (fix did not apply?)");
            }

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
