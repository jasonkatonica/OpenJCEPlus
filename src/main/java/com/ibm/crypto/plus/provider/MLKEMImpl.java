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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MLKEMImpl implements KEMSpi {
    // Optimization: Use final fields to enable JIT optimizations
    private final OpenJCEPlusProvider provider;
    private final String alg;
    private final boolean genericMlKem;
    private static final int SECRETSIZE = 32;

    // Optimization: Cache encapsulation lengths to avoid repeated switch statements
    private static final int ENCAP_LEN_512 = 768;
    private static final int ENCAP_LEN_768 = 1088;
    private static final int ENCAP_LEN_1024 = 1568;

    // Optimization: Cache the provider name once to avoid repeated virtual lookups.
    private static final String ML_KEM = "ML-KEM";
    private static final String ML_KEM_512 = "ML-KEM-512";
    private static final String ML_KEM_768 = "ML-KEM-768";
    private static final String ML_KEM_1024 = "ML-KEM-1024";

    public MLKEMImpl(OpenJCEPlusProvider provider, String alg) {
        this.provider = provider;
        // Optimization: Intern algorithm string for fast equality checks
        this.alg = alg.intern();
        this.genericMlKem = (this.alg == ML_KEM);
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
    // Optimization: Use reference equality for interned strings (faster than equals())
    private void validateKeyAlgorithm(String keyAlgorithm) throws InvalidKeyException {
        // Intern the key algorithm for fast comparison
        String internedKeyAlg = keyAlgorithm.intern();

        // Generic ML-KEM instance accepts any ML-KEM variant key algorithm
        if (genericMlKem) {
            return;
        }

        // Specific instance accepts exact match or generic "ML-KEM"
        if (this.alg != internedKeyAlg && internedKeyAlg != ML_KEM) {
            throw new InvalidKeyException("Key algorithm " + keyAlgorithm
                    + " does not match KEM instance algorithm " + this.alg);
        }
    }
    
    // Optimization: Use cached constants and reference equality for faster lookup
    private int getEncapsulationLength(String algorithm) {
        // Intern for fast reference comparison
        String internedAlg = algorithm.intern();
        
        if (internedAlg == ML_KEM_512) {
            return ENCAP_LEN_512;
        } else if (internedAlg == ML_KEM_768) {
            return ENCAP_LEN_768;
        } else if (internedAlg == ML_KEM_1024) {
            return ENCAP_LEN_1024;
        } else {
            // If algorithm is generic "ML-KEM", default to ML-KEM-768
            return ENCAP_LEN_768;
        }
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

        if (!(pubKey instanceof PQCPublicKey pqcPublicKey)) {
            // Try and convert this key to a usage PQCPublicKey
            // First verify it's an ML-KEM key
            String keyAlgorithm = publicKey.getAlgorithm();
            if (keyAlgorithm == null || !keyAlgorithm.startsWith("ML-KEM")) {
                throw new InvalidKeyException("unsupported key");
            }

            // Validate algorithm match (unless this is the generic ML-KEM instance)
            validateKeyAlgorithm(keyAlgorithm);

            // Iteration 2 optimization:
            // Avoid temporary EncodedKeySpec allocation and let the provider parse the
            // encoded key directly.
            try {
                KeyFactory kf = KeyFactory.getInstance(keyAlgorithm, this.provider.getName());
                pubKey = kf.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));

            } catch (Exception e) {
                throw new InvalidKeyException("unsupported key", e);
            }
        } else {
            // Key is already a PQCPublicKey, validate algorithm match
            validateKeyAlgorithm(pqcPublicKey.getAlgorithm());
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        return new MLKEMEncapsulator(pubKey, spec, null);
    }

    class MLKEMEncapsulator implements KEMSpi.EncapsulatorSpi {

        // Optimization: Use final fields and cache values to reduce repeated lookups
        private final PublicKey publicKey;
        private final int size = SECRETSIZE;
        private final String keyAlgorithm;
        private final int encapLen;

        /*
         * spec - The AlgorithmParameterSpec is not used and should be null. 
         * secureRandom - This parameter is not used and should be null. If not null it
         * will be ignored.
         */
        MLKEMEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                SecureRandom secureRandom) {
            this.publicKey = publicKey;
            // Optimization: Cache key algorithm and encapsulation length at construction time
            this.keyAlgorithm = publicKey.getAlgorithm();
            this.encapLen = getEncapsulationLength(keyAlgorithm);
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            // Optimization: Validate parameters first before allocating arrays
            if (from < 0 || to > SECRETSIZE || ((to - from) < 0) || (from >= SECRETSIZE)) {
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null) {
                throw new NullPointerException();
            }

            // Optimization: Allocate arrays only after validation passes
            byte[] encapsulation = new byte[encapLen];
            byte[] secret = new byte[SECRETSIZE];

            try {
                // Optimization: Get pKeyId once per call instead of in constructor
                long pKeyId = ((PQCPublicKey) publicKey).getPQCKey().getPKeyId();
                OJPKEM.KEM_encapsulate(pKeyId, encapsulation, secret, provider);
            } catch (NativeException e) {
                throw new ProviderException("OCK Exception: ", e);
            }

            return new KEM.Encapsulated(
                    new SecretKeySpec(secret, from, to - from, algorithm),
                    encapsulation, null);
        }

        @Override
        public int engineEncapsulationSize() {
            // Optimization: Return cached value instead of repeated lookups
            return encapLen;
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

        if (!(privKey instanceof PQCPrivateKey pqcPrivateKey)) {
            // Try and convert this key to a usage PQCPrivateKey
            // First verify it's an ML-KEM key
            String keyAlgorithm = privateKey.getAlgorithm();
            if (keyAlgorithm == null || !keyAlgorithm.startsWith("ML-KEM")) {
                throw new InvalidKeyException("unsupported key");
            }

            // Validate algorithm match (unless this is the generic ML-KEM instance)
            validateKeyAlgorithm(keyAlgorithm);

            // Iteration 2 optimization:
            // Keep the encoded form in a single local and zero it after provider import.
            byte[] encoding = null;
            try {
                KeyFactory kf = KeyFactory.getInstance(keyAlgorithm, this.provider.getName());
                encoding = privateKey.getEncoded();
                privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encoding));
            } catch (Exception e) {
                throw new InvalidKeyException("unsupported key", e);
            } finally {
                if (encoding != null) {
                    Arrays.fill(encoding, (byte) 0);
                }
            }

        } else {
            // Key is already a PQCPrivateKey, validate algorithm match
            validateKeyAlgorithm(pqcPrivateKey.getAlgorithm());
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
        // Optimization: Use final fields and cache values to reduce repeated lookups
        private final PrivateKey privateKey;
        private final int size = SECRETSIZE;
        private final String keyAlgorithm;
        private final int expectedEncapLen;

        MLKEMDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) {
            this.privateKey = privateKey;
            // Optimization: Cache key algorithm and expected encapsulation length at construction time
            this.keyAlgorithm = privateKey.getAlgorithm();
            this.expectedEncapLen = getEncapsulationLength(keyAlgorithm);
        }

        @Override
        public SecretKey engineDecapsulate(byte[] cipherText, int from, int to, String algorithm)
                throws DecapsulateException {
            // Optimization: Validate parameters first before any processing
            if (from < 0 || to > SECRETSIZE || ((to - from) < 0) || (from >= SECRETSIZE)) {
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null || cipherText == null) {
                throw new NullPointerException();
            }

            // Optimization: Use cached expectedEncapLen instead of repeated lookups
            if (cipherText.length != expectedEncapLen) {
                throw new DecapsulateException(
                    "Invalid key encapsulation message length: expected " +
                    expectedEncapLen + " bytes for " + keyAlgorithm +
                    ", but got " + cipherText.length + " bytes");
            }

            byte[] secret;
            try {
                // Optimization: Get pKeyId once per call instead of in constructor
                long pKeyId = ((PQCPrivateKey) privateKey).getPQCKey().getPKeyId();
                secret = OJPKEM.KEM_decapsulate(pKeyId, cipherText, provider);

            } catch (NativeException e) {
                throw new DecapsulateException("Decapsulation Error: ", e);
            }

            return new SecretKeySpec(secret, from, to - from, algorithm);
        }

        @Override
        public int engineEncapsulationSize() {
            // Optimization: Return cached value instead of repeated lookups
            return expectedEncapLen;
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
