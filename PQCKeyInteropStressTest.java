/*
 * Copyright IBM Corp. 2023, 2026
 *
 * Standalone PQC Key Interop Stress Test
 * 
 * This is a completely standalone test that reproduces intermittent
 * PQC key interoperability failures between OpenJCEPlus and SunJCE.
 * 
 * Compile: javac -cp target/classes PQCKeyInteropStressTest.java
 * Run:     java -cp .:target/classes PQCKeyInteropStressTest
 */

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

/**
 * Standalone stress test to reproduce intermittent PQC Key Interop failures
 * between OpenJCEPlus and SunJCE providers.
 */
public class PQCKeyInteropStressTest {

    private static final String PROVIDER_OPENJCEPLUS = "OpenJCEPlus";
    private static final String PROVIDER_SUNJCE = "SunJCE";
    private static final String PROVIDER_SUN = "SUN";
    
    private static int totalIterations = 0;
    private static int failureCount = 0;
    
    public static void main(String[] args) throws Exception {
        // Check Java version
        String javaVersion = System.getProperty("java.version");
        System.out.println("Java Version: " + javaVersion);
        
        // Load OpenJCEPlus provider
        try {
            Class<?> providerClass = Class.forName("com.ibm.crypto.plus.provider.OpenJCEPlus");
            Security.addProvider((java.security.Provider) providerClass.getDeclaredConstructor().newInstance());
            System.out.println("OpenJCEPlus provider loaded successfully");
        } catch (Exception e) {
            System.err.println("ERROR: Failed to load OpenJCEPlus provider");
            System.err.println("Make sure target/classes is in the classpath");
            e.printStackTrace();
            System.exit(1);
        }
        
        System.out.println("=".repeat(80));
        System.out.println("PQC Key Interop Stress Test - Continuous Loop");
        System.out.println("Testing OpenJCEPlus vs SunJCE interoperability");
        System.out.println("Press Ctrl+C to stop");
        System.out.println("=".repeat(80));
        System.out.println();
        
        // Run tests in infinite loop
        while (true) {
            totalIterations++;
            
            System.out.println("\n" + "=".repeat(80));
            System.out.println("Iteration #" + totalIterations + " - Failures so far: " + failureCount);
            System.out.println("=".repeat(80));
            
            try {
                // Test 1: KEM Auto Key Conversion
                testKEMAutoKeyConversion();
                
                // Test 2: KEM Interop (OpenJCEPlus keys with SunJCE)
                testKEMInteropPlusToSunJCE();
                
                // Test 3: KEM Interop (SunJCE keys with OpenJCEPlus)
                testKEMInteropSunJCEToPlus();
                
                // Test 4: ML-KEM with empty params
                testMLKEMEmptyParams("ML-KEM-512");
                testMLKEMEmptyParams("ML-KEM-768");
                testMLKEMEmptyParams("ML-KEM-1024");
                
                // Test 5: ML-KEM with all algorithms
                testKEMInteropKeyPlusAll("ML-KEM");
                testKEMInteropKeyPlusAll("ML-KEM-512");
                testKEMInteropKeyPlusAll("ML-KEM-768");
                testKEMInteropKeyPlusAll("ML-KEM-1024");
                
                // Test 6: ML-DSA Signature Interop
                testMLDSASignatureInterop("ML-DSA-44");
                testMLDSASignatureInterop("ML-DSA-65");
                testMLDSASignatureInterop("ML-DSA-87");
                
                System.out.println("\n✓ Iteration #" + totalIterations + " PASSED");
                
            } catch (Exception e) {
                failureCount++;
                System.err.println("\n✗ FAILURE detected in iteration #" + totalIterations);
                System.err.println("Failure count: " + failureCount + " out of " + totalIterations);
                System.err.println("Failure rate: " + String.format("%.2f%%", (failureCount * 100.0 / totalIterations)));
                e.printStackTrace();
                System.err.println();
            }
            
            // Small delay to prevent overwhelming the system
            Thread.sleep(100);
        }
    }
    
    /**
     * Test KEM auto key conversion between providers
     * Reproduces: testPQCKeyGenKEMAutoKeyConvertion failure
     */
    private static void testKEMAutoKeyConversion() throws Exception {
        System.out.println("\n[Test] KEM Auto Key Conversion (SunJCE -> OpenJCEPlus)");
        
        String algorithm = "ML-KEM-512";
        
        // Generate keys with SunJCE
        KeyPairGenerator keyPairGenSunJCE = KeyPairGenerator.getInstance(algorithm, PROVIDER_SUNJCE);
        KeyPair keyPairSunJCE = keyPairGenSunJCE.generateKeyPair();
        
        // Convert SunJCE keys to OpenJCEPlus format via KeyFactory
        KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyPairSunJCE.getPrivate().getEncoded());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyPairSunJCE.getPublic().getEncoded());
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpec);
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpec);
        
        // Use OpenJCEPlus KEM with converted keys
        KEM kemPlus = KEM.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
        
        if (enc == null) {
            throw new RuntimeException("Encapsulation returned null");
        }
        
        SecretKey keyE = enc.key();
        KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");
        
        if (!Arrays.equals(keyE.getEncoded(), keyD.getEncoded())) {
            throw new RuntimeException("Secrets do NOT match - encap key: " +
                bytesToHex(keyE.getEncoded(), 8) + " vs decap key: " +
                bytesToHex(keyD.getEncoded(), 8));
        }
        
        System.out.println("  ✓ Secrets match");
    }
    
    /**
     * Test KEM interop: OpenJCEPlus creates keys, SunJCE uses them
     * Reproduces: testPQCKeyGenKEM_Interop failure
     */
    private static void testKEMInteropPlusToSunJCE() throws Exception {
        System.out.println("\n[Test] KEM Interop (OpenJCEPlus keys -> SunJCE operations)");
        
        String algorithm = "ML-KEM-512";
        
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        KeyFactory keyFactorySunJCE = KeyFactory.getInstance(algorithm, PROVIDER_SUNJCE);
        
        KeyPair keyPairPlus = keyPairGenPlus.generateKeyPair();
        PublicKey publicKeyPlus = keyPairPlus.getPublic();
        PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        
        byte[] publicKeyBytes = publicKeyPlus.getEncoded();
        byte[] privateKeyBytes = privateKeyPlus.getEncoded();
        
        // Convert keys to SunJCE
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKeySunJCE = keyFactorySunJCE.generatePublic(publicKeySpec);
        PrivateKey privateKeySunJCE = keyFactorySunJCE.generatePrivate(privateKeySpec);
        
        // Verify key encoding matches
        if (!Arrays.equals(privateKeyBytes, privateKeySunJCE.getEncoded())) {
            throw new RuntimeException("Private key encoding mismatch");
        }
        if (!Arrays.equals(publicKeyBytes, publicKeySunJCE.getEncoded())) {
            throw new RuntimeException("Public key encoding mismatch");
        }
        
        System.out.println("  ✓ Key conversion successful");
    }
    
    /**
     * Test KEM interop: SunJCE creates keys, OpenJCEPlus uses them
     * Reproduces: testPQCKeyGenKEM_PlusToInteropRAW failure
     */
    private static void testKEMInteropSunJCEToPlus() throws Exception {
        System.out.println("\n[Test] KEM Interop (SunJCE keys -> OpenJCEPlus operations)");
        
        String algorithm = "ML-KEM-512";
        
        KEM kemPlus = KEM.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        KeyPairGenerator keyPairGenSunJCE = KeyPairGenerator.getInstance(algorithm, PROVIDER_SUNJCE);
        KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        
        KeyPair keyPairSunJCE = keyPairGenSunJCE.generateKeyPair();
        PublicKey publicKeySunJCE = keyPairSunJCE.getPublic();
        PrivateKey privateKeySunJCE = keyPairSunJCE.getPrivate();
        
        // Convert keys to OpenJCEPlus
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeySunJCE.getEncoded());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeySunJCE.getEncoded());
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpec);
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpec);
        
        // Test encapsulation/decapsulation
        KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
        
        if (enc == null) {
            throw new RuntimeException("Encapsulation returned null");
        }
        
        SecretKey keyE = enc.key();
        KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");
        
        if (!Arrays.equals(keyE.getEncoded(), keyD.getEncoded())) {
            throw new RuntimeException("Secrets do NOT match - encap key: " + 
                bytesToHex(keyE.getEncoded(), 8) + " vs decap key: " + 
                bytesToHex(keyD.getEncoded(), 8));
        }
        
        System.out.println("  ✓ Secrets match");
    }
    
    /**
     * Test ML-KEM with empty parameters using NamedParameterSpec
     * Reproduces: testMLKEMInteropEmptyParamsWithNamedParameterSpec failure
     */
    private static void testMLKEMEmptyParams(String parameterSet) throws Exception {
        System.out.println("\n[Test] ML-KEM Empty Params: " + parameterSet);
        
        // Generate key pair using SunJCE with specific parameter set
        KeyPairGenerator keyPairGenSunJCE = KeyPairGenerator.getInstance(parameterSet, PROVIDER_SUNJCE);
        KeyPair keyPairSunJCE = keyPairGenSunJCE.generateKeyPair();
        
        // Encapsulate using SunJCE (no from/to parameters)
        KEM kemSunJCE = KEM.getInstance(parameterSet, PROVIDER_SUNJCE);
        KEM.Encapsulator encapsulator = kemSunJCE.newEncapsulator(keyPairSunJCE.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Convert SunJCE private key to OpenJCEPlus format using matching algorithm
        KeyFactory keyFactoryPlus = KeyFactory.getInstance(parameterSet, PROVIDER_OPENJCEPLUS);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyPairSunJCE.getPrivate().getEncoded());
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpec);
        
        // Decapsulate using OpenJCEPlus (no from/to parameters)
        KEM kemPlus = KEM.getInstance(parameterSet, PROVIDER_OPENJCEPLUS);
        KEM.Decapsulator decapsulator = kemPlus.newDecapsulator(privateKeyPlus);
        SecretKey decapKey = decapsulator.decapsulate(encapsulation);
        
        // Verify that both keys match
        if (!Arrays.equals(encapKey.getEncoded(), decapKey.getEncoded())) {
            throw new RuntimeException("Encapsulated and decapsulated keys do not match for " +
                parameterSet + " - encap key: " + bytesToHex(encapKey.getEncoded(), 8) +
                " vs decap key: " + bytesToHex(decapKey.getEncoded(), 8));
        }
        
        System.out.println("  ✓ Keys match for " + parameterSet);
    }
    
    /**
     * Test KEM interop with all ML-KEM algorithms
     * Reproduces: testKEMInteropKeyPlusAll failure
     */
    private static void testKEMInteropKeyPlusAll(String algorithm) throws Exception {
        System.out.println("\n[Test] KEM Interop Key Plus All: " + algorithm);
        
        KEM kemPlus = KEM.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        
        KeyPairGenerator keyPairGenInterop = KeyPairGenerator.getInstance(algorithm, PROVIDER_SUNJCE);
        KeyPair keyPairInterop = keyPairGenInterop.generateKeyPair();
        
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        
        PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyInterop.getEncoded());
        X509EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());
        KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
        
        KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
        if (enc == null) {
            throw new RuntimeException("Encapsulation returned null");
        }
        SecretKey keyE = enc.key();
        
        KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");
        
        if (!Arrays.equals(keyE.getEncoded(), keyD.getEncoded())) {
            throw new RuntimeException("Secrets do NOT match for " + algorithm + 
                " - encap key: " + bytesToHex(keyE.getEncoded(), 8) + 
                " vs decap key: " + bytesToHex(keyD.getEncoded(), 8));
        }
        
        System.out.println("  ✓ Secrets match for " + algorithm);
    }
    
    /**
     * Test ML-DSA signature interop
     * Reproduces: testSignInteropKeysPlusSignVerify failure
     */
    private static void testMLDSASignatureInterop(String algorithm) throws Exception {
        System.out.println("\n[Test] ML-DSA Signature Interop: " + algorithm);
        
        byte[] message = "This is a test message for ML-DSA signature".getBytes();
        
        // Generate key pair with OpenJCEPlus
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        KeyPair keyPairPlus = keyPairGenPlus.generateKeyPair();
        
        // Sign with OpenJCEPlus
        Signature signerPlus = Signature.getInstance(algorithm, PROVIDER_OPENJCEPLUS);
        signerPlus.initSign(keyPairPlus.getPrivate());
        signerPlus.update(message);
        byte[] signature = signerPlus.sign();
        
        // Verify with SUN provider
        Signature verifierSun = Signature.getInstance(algorithm, PROVIDER_SUN);
        verifierSun.initVerify(keyPairPlus.getPublic());
        verifierSun.update(message);
        boolean verified = verifierSun.verify(signature);
        
        if (!verified) {
            throw new RuntimeException("Signature verification failed for " + algorithm);
        }
        
        System.out.println("  ✓ Signature verified for " + algorithm);
    }
    
    /**
     * Convert byte array to hex string (first n bytes)
     */
    private static String bytesToHex(byte[] bytes, int maxBytes) {
        if (bytes == null) return "null";
        int len = Math.min(bytes.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bytes[i]));
            if (i < len - 1) sb.append(" ");
        }
        if (bytes.length > maxBytes) {
            sb.append("...");
        }
        return sb.toString();
    }
}

// Made with Bob
