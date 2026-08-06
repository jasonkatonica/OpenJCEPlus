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

    /** Debug helper: hex-encode the first 16 bytes of a byte array. */
    private static String toHex16(byte[] b) {
        if (b == null || b.length == 0) return "(empty)";
        StringBuilder sb = new StringBuilder();
        int len = Math.min(b.length, 16);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", b[i] & 0xFF));
        }
        return sb.toString();
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

            PQCKey pqcPubKey = ((PQCPublicKey) publicKey).getPQCKey();
            long pubPKeyId = 0;
            try {
                pubPKeyId = pqcPubKey.getPKeyId();
                // GAP #2 fix: dump Java-side public key bytes before the native call so
                // they can be correlated with the C-side ICC_i2d_PublicKey dump in KEM_encapsulate.
                // BIT STRING format: 03 82 xx xx 00 <raw key bytes>; raw starts at offset 5.
                byte[] pubKB = pqcPubKey.getPublicKeyBytes();
                String pubKBfirst16 = "(null)";
                String pubKBrawFirst16 = "(null)";
                if (pubKB != null) {
                    pubKBfirst16  = pubKB.length >= 16 ? toHex16(pubKB) : "(short)";
                    pubKBrawFirst16 = pubKB.length >= 21
                        ? toHex16(java.util.Arrays.copyOfRange(pubKB, 5, 21)) : "(short)";
                }
                System.err.printf("[MLKEMImpl] DEBUG: encapsulate alg=%s pubKey.identityHash=0x%x"
                        + " pqcPubKey.identityHash=0x%x pubPKeyId=0x%x thread=%d"
                        + " pubKeyBytes.len=%d pubKeyBytes.first16=%s pubKeyRawFirst16=%s%n",
                        algName, System.identityHashCode(publicKey),
                        System.identityHashCode(pqcPubKey),
                        pubPKeyId, Thread.currentThread().getId(),
                        pubKB != null ? pubKB.length : -1,
                        pubKBfirst16, pubKBrawFirst16);
                System.err.flush();
                OJPKEM.KEM_encapsulate(pubPKeyId,
                        encapsulation, secret, provider, algName);
                // GAP #2 (output side): print the produced ciphertext and secret first16
                System.err.printf("[MLKEMImpl] DEBUG: encapsulate done alg=%s pubPKeyId=0x%x"
                        + " thread=%d cipherFirst16=%s secretFirst16=%s%n",
                        algName, pubPKeyId, Thread.currentThread().getId(),
                        toHex16(encapsulation), toHex16(secret));
                System.err.flush();
            } catch (NativeException e) {
                throw new ProviderException("OCK Exception: ", e);
            } finally {
                // Fence on both the inner PQCKey AND the wrapper that holds it.
                // Fencing only pqcPubKey is not enough: if the PQCPublicKey
                // wrapper becomes unreachable before the JNI call returns, the
                // GC can collect it -> cleaner fires MLKEY_delete on the same
                // EVP_PKEY* still in use by KEM_encapsulate.
                Reference.reachabilityFence(pqcPubKey);
                Reference.reachabilityFence(publicKey);
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

            PQCKey pqcPrivKey = ((PQCPrivateKey) this.privateKey).getPQCKey();
            long privPKeyId = 0;
            try {
                privPKeyId = pqcPrivKey.getPKeyId();
                // Print public key bytes stored in the private key object for correlation.
                // pqcPrivKey.getPublicKeyBytes() returns ICC's raw format which starts with
                // a BIT STRING header (03 82 xx xx 00), so offset 5 onward is the raw key.
                // Compare first16 at offset 5 with "pubPlus raw key first16" in the test log
                // and with "[KEM_decapsulate] DEBUG: ockPKey pub key first16" in C.
                byte[] privPubBytes = pqcPrivKey.getPublicKeyBytes();
                String privPubFirst16 = "(null)";
                String privPubRawFirst16 = "(null)";
                if (privPubBytes != null) {
                    privPubFirst16 = privPubBytes.length >= 16 ? toHex16(privPubBytes) : "(short)";
                    // Skip 5-byte BIT STRING header: 03 82 xx xx 00
                    privPubRawFirst16 = privPubBytes.length >= 21
                        ? toHex16(java.util.Arrays.copyOfRange(privPubBytes, 5, 21)) : "(short)";
                }
                // Print ciphertext first16 so it can be matched to C-side ciphertext print
                String cipherFirst16 = toHex16(cipherText);
                System.err.printf("[MLKEMImpl] DEBUG: decapsulate alg=%s privKey.identityHash=0x%x"
                        + " pqcPrivKey.identityHash=0x%x privPKeyId=0x%x thread=%d"
                        + " cipherText.length=%d cipherFirst16=%s"
                        + " privPubKeyBytes.len=%d"
                        + " privPubKeyBytes.first16=%s rawKeyFirst16=%s%n",
                        algName, System.identityHashCode(this.privateKey),
                        System.identityHashCode(pqcPrivKey),
                        privPKeyId, Thread.currentThread().getId(),
                        cipherText.length, cipherFirst16,
                        privPubBytes != null ? privPubBytes.length : -1,
                        privPubFirst16,
                        privPubRawFirst16);
                System.err.flush();
                secret = OJPKEM.KEM_decapsulate(privPKeyId,
                        cipherText, provider, algName);
                System.err.printf("[MLKEMImpl] DEBUG: decapsulate completed alg=%s privPKeyId=0x%x"
                        + " thread=%d secret.length=%d%n",
                        algName, privPKeyId, Thread.currentThread().getId(),
                        (secret != null ? secret.length : -1));
                System.err.flush();
            } catch (NativeException e) {
                throw new DecapsulateException("Decapsulation Error: ", e);
            } finally {
                // Fence on both the inner PQCKey AND the wrapper that holds it.
                // Fencing only pqcPrivKey is not enough: if the PQCPrivateKey
                // wrapper (this.privateKey) becomes unreachable before the JNI
                // call returns, the GC can collect it -> cleaner fires
                // MLKEY_delete on the pkeyId still being used by KEM_decapsulate.
                Reference.reachabilityFence(pqcPrivKey);
                Reference.reachabilityFence(this.privateKey);
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
}
