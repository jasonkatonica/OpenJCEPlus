/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.NativeException;
import com.ibm.crypto.plus.provider.base.OJPKEM;
import com.ibm.crypto.plus.provider.base.PQCKey;
import java.lang.ref.Reference;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MLKEMImpl implements KEMSpi {
    OpenJCEPlusProvider provider;
    String alg;
    static int SECRETSIZE  = 32;

    public MLKEMImpl(OpenJCEPlusProvider provider, String alg) {
        this.provider = provider;
        this.alg = alg;
    }
    
    /**
     * Validates that the key's algorithm matches this KEM instance's algorithm.
     * The generic "ML-KEM" instance accepts keys from any ML-KEM variant.
     * Specific instances (ML-KEM-512, ML-KEM-768, ML-KEM-1024) accept:
     * - Keys with matching specific algorithm (e.g., ML-KEM-512)
     * - Keys with generic "ML-KEM" algorithm (for interop with providers that use generic naming)
     *
     * @param keyAlgorithm the algorithm from the key
     * @throws InvalidKeyException if the key algorithm doesn't match the instance algorithm
     */
    private void validateKeyAlgorithm(String keyAlgorithm) throws InvalidKeyException {
        // Generic ML-KEM instance accepts any ML-KEM variant key algorithm
        if (this.alg.equals("ML-KEM")) {
            return;
        }
        
        // Specific instance accepts exact match or generic "ML-KEM"
        if (!this.alg.equals(keyAlgorithm) && !keyAlgorithm.equals("ML-KEM")) {
            throw new InvalidKeyException("Key algorithm " + keyAlgorithm +
                " does not match KEM instance algorithm " + this.alg);
        }
    }
    
    private int getEncapsulationLength(String algorithm) {
        int size = 0;

        switch (algorithm) {
            case "ML-KEM-512":
                size = 768;
                break;
            case "ML-KEM-768":
                size = 1088;
                break;
            case "ML-KEM-1024":
                size = 1568;
                break;
            default:
                // If algorithm is generic "ML-KEM", default to ML-KEM-768
                size = 1088;
        }
        return size;
    }

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
     * secureRandom - This parameter is not used and should be null. If not null it
     * will be ignored.
     */
    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
            AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        
        PublicKey pubKey = publicKey;
        if (pubKey == null) {
            throw new InvalidKeyException("Key is null.");
        }

        if (!(pubKey instanceof PQCPublicKey)) {
            // Try and convert this key to a usage PQCPublicKey
            // First verify it's an ML-KEM key
            String keyAlgorithm = publicKey.getAlgorithm();
            if (keyAlgorithm == null || !keyAlgorithm.startsWith("ML-KEM")) {
                throw new InvalidKeyException("unsupported key");
            }
            
            // Validate algorithm match (unless this is the generic ML-KEM instance)
            validateKeyAlgorithm(keyAlgorithm);
            
            // === PROBE D: inspect the foreign key's encoded form before conversion ===
            // The SubjectPublicKeyInfo BIT STRING for ML-KEM has this layout:
            //   30 xx xx  (SEQUENCE - outer SPKI)
            //     30 xx   (SEQUENCE - AlgorithmIdentifier)  ...variable...
            //     03 82 xx xx <unusedBits> <payload>   (BIT STRING - public key)
            // We locate the BIT STRING tag (0x03) by scanning for it.
            // The critical byte is <unusedBits>: if non-zero AND the provider that
            // produced this key (e.g. BC) preserved it, ctor-3's X509Key.decode()
            // will store a BitArray with a non-multiple-of-8 bit-count, and the
            // subsequent toByteArray() will return a truncated/shifted payload.
            byte[] foreignEncoded = publicKey.getEncoded();
            System.out.println("[DBG MLKEMImpl encap] PROBE-D foreign key:"
                    + " provider=" + publicKey.getClass().getName()
                    + " alg=" + keyAlgorithm
                    + " encoded.length=" + foreignEncoded.length
                    + " encoded[0..4]=" + hex4(foreignEncoded));
            // Scan for the BIT STRING tag (0x03) inside the SPKI to find unusedBits
            // and the first 8 payload bytes so we can compare them byte-for-byte with
            // what ctor-3 eventually sends to OCK (PROBE-B payload[0..7]).
            for (int idx = 1; idx < foreignEncoded.length - 9; idx++) {
                if ((foreignEncoded[idx] & 0xff) == 0x03) {
                    // Candidate BIT STRING — check length form
                    int ub = -1; int hdr = -1;
                    if ((foreignEncoded[idx + 1] & 0xff) == 0x82 && idx + 4 < foreignEncoded.length) {
                        ub = foreignEncoded[idx + 4] & 0xff; hdr = idx + 5;
                    } else if ((foreignEncoded[idx + 1] & 0xff) == 0x81 && idx + 3 < foreignEncoded.length) {
                        ub = foreignEncoded[idx + 3] & 0xff; hdr = idx + 4;
                    } else if ((foreignEncoded[idx + 1] & 0x80) == 0 && idx + 2 < foreignEncoded.length) {
                        ub = foreignEncoded[idx + 2] & 0xff; hdr = idx + 3;
                    }
                    if (ub >= 0 && hdr + 8 <= foreignEncoded.length) {
                        byte[] payload8 = Arrays.copyOfRange(foreignEncoded, hdr, hdr + 8);
                        System.out.println("[DBG MLKEMImpl encap] PROBE-D BIT STRING at offset " + idx
                                + ": unusedBits=" + ub
                                + " payload[0..7]=" + hex4ext(payload8)
                                + (ub != 0 ? " *** NON-ZERO unusedBits ***" : " (ok)"));
                        break;
                    }
                }
            }

            // Use the key's actual algorithm, not the generic "ML-KEM"
            try {
                KeyFactory kf = KeyFactory.getInstance(keyAlgorithm, this.provider.getName());
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
                pubKey = kf.generatePublic(publicKeySpec);
       
            } catch (Exception e) {
                throw new InvalidKeyException("unsupported key", e);
            }
        } else {
            // Key is already a PQCPublicKey, validate algorithm match
            validateKeyAlgorithm(pubKey.getAlgorithm());
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        return new MLKEMEncapsulator(pubKey, spec, null);
    }

    class MLKEMEncapsulator implements KEMSpi.EncapsulatorSpi {

        PublicKey publicKey;
        int size = SECRETSIZE;
        String algName = null;

        /*
         * spec - The AlgorithmParameterSpec is not used and should be null. 
         * secureRandom - This parameter is not used and should be null. If not null it
         * will be ignored.
         */
        MLKEMEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                SecureRandom secureRandom) {
            this.publicKey = publicKey;
            this.algName = ((PQCPublicKey) publicKey).getAlgorithm().replace('_', '-');
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            // Get the actual algorithm from the public key
            String keyAlgorithm = publicKey.getAlgorithm();
            int encapLen = getEncapsulationLength(keyAlgorithm);
            byte[] encapsulation = new byte[encapLen];
            byte[] secret = new byte[SECRETSIZE];

            if (from < 0 || to > SECRETSIZE || ((to - from) < 0) || (from >= SECRETSIZE)) {
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null) {
                throw new NullPointerException();
            }

            PQCPublicKey pqcPubKey = (PQCPublicKey) this.publicKey;
            PQCKey pqcKeyPub = pqcPubKey.getPQCKey();
            try {
                // PROBE-C: log pkeyId so we can correlate which OCK key handle was used,
                // and the first 8 bytes of ciphertext and secret after encapsulation.
                System.out.println("[DBG MLKEMImpl encap] PROBE-C before encap:"
                        + " alg=" + algName
                        + " pkeyId=" + pqcKeyPub.getPKeyId());
                OJPKEM.KEM_encapsulate(pqcKeyPub.getPKeyId(),
                        encapsulation, secret, provider, algName);
                System.out.println("[DBG MLKEMImpl encap] PROBE-C after encap:"
                        + " ciphertext[0..7]=" + hex4ext(Arrays.copyOf(encapsulation, Math.min(8, encapsulation.length)))
                        + " secret[0..7]=" + hex4ext(Arrays.copyOf(secret, Math.min(8, secret.length))));
            } catch (NativeException e) {
                throw new ProviderException("OCK Exception: ", e);
            } finally {
                Reference.reachabilityFence(pqcKeyPub);
            }

            return new KEM.Encapsulated(
                    new SecretKeySpec(secret, from, to - from, algorithm),
                    encapsulation, null);
        }

        @Override
        public int engineEncapsulationSize() {
            String keyAlgorithm = publicKey.getAlgorithm();
            return getEncapsulationLength(keyAlgorithm);
        }

        @Override
        public int engineSecretSize() {
            return this.size;
        }
    }

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. 
     */
    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
            AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
 
        PrivateKey privKey = privateKey;

        if (privKey == null) {
            throw new InvalidKeyException("Key is null.");
        }

        if (!(privKey instanceof PQCPrivateKey)) {
            // Try and convert this key to a usage PQCPrivateKey
            // First verify it's an ML-KEM key
            String keyAlgorithm = privateKey.getAlgorithm();
            if (keyAlgorithm == null || !keyAlgorithm.startsWith("ML-KEM")) {
                throw new InvalidKeyException("unsupported key");
            }
            
            // Validate algorithm match (unless this is the generic ML-KEM instance)
            validateKeyAlgorithm(keyAlgorithm);
            
            // Use the key's actual algorithm, not the generic "ML-KEM"
            byte[] encoding = null;
            try {
                KeyFactory kf = KeyFactory.getInstance(keyAlgorithm, this.provider.getName());
                encoding = privateKey.getEncoded();
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encoding);
                privKey = kf.generatePrivate(privateKeySpec);
            } catch (Exception e) {
                throw new InvalidKeyException("unsupported key", e);
            } finally {
                Arrays.fill(encoding, (byte) 0);
            }

        } else {
            // Key is already a PQCPrivateKey, validate algorithm match
            validateKeyAlgorithm(privKey.getAlgorithm());
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        return new MLKEMDecapsulator(privKey, null);
    }

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. 
     */
    class MLKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        PrivateKey privateKey;
        int size = SECRETSIZE;
        String algName = null;

        MLKEMDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) {
            this.privateKey = privateKey;
            this.algName = ((PQCPrivateKey) privateKey).getAlgorithm().replace('_', '-');
        }

        @Override
        public SecretKey engineDecapsulate(byte[] cipherText, int from, int to, String algorithm)
                throws DecapsulateException {
            byte[] secret;

            if (from < 0 || to > SECRETSIZE || ((to - from) < 0) || (from >= SECRETSIZE)) {
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null || cipherText == null) {
                throw new NullPointerException();
            }

            // Validate encapsulation length matches the key's algorithm
            String keyAlgorithm = privateKey.getAlgorithm();
            int expectedEncapLen = getEncapsulationLength(keyAlgorithm);
            if (cipherText.length != expectedEncapLen) {
                throw new DecapsulateException(
                    "Invalid key encapsulation message length: expected " +
                    expectedEncapLen + " bytes for " + keyAlgorithm +
                    ", but got " + cipherText.length + " bytes");
            }

            PQCPrivateKey pqcPrivKey = (PQCPrivateKey) this.privateKey;
            PQCKey pqcKeyPriv = pqcPrivKey.getPQCKey();
            try {
                // PROBE-E: log the private key's pkeyId and the first 8 bytes of the
                // resulting secret so we can cross-check with PROBE-C on the encap side.
                // pkeyId here is a DIFFERENT handle from the encap-side pkeyId — that is
                // expected. What must match is secret[0..7] == PROBE-C secret[0..7].
                System.out.println("[DBG MLKEMImpl decap] PROBE-E before decap:"
                        + " alg=" + algName
                        + " privKeyPkeyId=" + pqcKeyPriv.getPKeyId()
                        + " ciphertext[0..7]=" + hex4ext(Arrays.copyOf(cipherText, Math.min(8, cipherText.length))));
                secret = OJPKEM.KEM_decapsulate(pqcKeyPriv.getPKeyId(),
                        cipherText, provider, algName);
                System.out.println("[DBG MLKEMImpl decap] PROBE-E after decap:"
                        + " secret[0..7]=" + hex4ext(Arrays.copyOf(secret, Math.min(8, secret.length))));
            } catch (NativeException e) {
                throw new DecapsulateException("Decapsulation Error: ", e);
            } finally {
                Reference.reachabilityFence(pqcKeyPriv);
            }

            return new SecretKeySpec(secret, from, to - from, algorithm);
        }

        @Override
        public int engineEncapsulationSize() {
            String keyAlgorithm = privateKey.getAlgorithm();
            return getEncapsulationLength(keyAlgorithm);
        }

        @Override
        public int engineSecretSize() {

            return this.size;
        }

    }

    public static final class MLKEM extends MLKEMImpl {

        public MLKEM(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM");
        }
    }

    public static final class MLKEM512 extends MLKEMImpl {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
        }
    }

    public static final class MLKEM768 extends MLKEMImpl {

        public MLKEM768(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-768");
        }
    }

    public static final class MLKEM1024 extends MLKEMImpl {

        public MLKEM1024(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-1024");
        }
    }

    /** Debug helper: hex-encodes the first 5 bytes of a byte array (for PROBE-D header). */
    private static String hex4(byte[] b) {
        if (b == null) return "<null>";
        int len = Math.min(5, b.length);
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) sb.append(String.format("%02x", b[i] & 0xff));
        return sb.toString();
    }

    /** Debug helper: hex-encodes up to 8 bytes of a byte array (for PROBE-C and PROBE-D payload). */
    private static String hex4ext(byte[] b) {
        if (b == null) return "<null>";
        int len = Math.min(8, b.length);
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) sb.append(String.format("%02x", b[i] & 0xff));
        return sb.toString();
    }
}
