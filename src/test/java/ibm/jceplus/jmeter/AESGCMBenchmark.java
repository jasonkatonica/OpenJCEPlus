package ibm.jceplus.jmeter;
/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;

/**
 * JMeter benchmark for AES-GCM performance.
 */
public class AESGCMBenchmark extends AbstractJavaSamplerClient {

    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 16 bytes
    private static final int KEY_SIZE = 256; // bits
    
    private SecretKey secretKey;
    private byte[] iv;
    private byte[] randomData;
    private int dataSize;
    private String operation;
    private Cipher cipher = null;
    private SecureRandom random = new SecureRandom();
    private String provider;

    @Override
    public void setupTest(JavaSamplerContext context) {
        operation = context.getParameter("operation");
        dataSize = Integer.parseInt(context.getParameter("dataSize"));
        provider = context.getParameter("provider");
        
        try {
            Provider provider2 = java.security.Security.getProvider("OpenJCEPlus");
            if (provider2 == null) {
                provider2 = (Provider) Class.forName("com.ibm.crypto.plus.provider.OpenJCEPlus").getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(provider2, 1);

            // Generate a random AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES",provider);
            keyGen.init(KEY_SIZE);
            secretKey = keyGen.generateKey();

            cipher = Cipher.getInstance("AES/GCM/NoPadding",provider);
            
            // Generate a random IV
            iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);
            
            // Generate random data for encryption based on specified size
            randomData = new byte[dataSize];
            random.nextBytes(randomData);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    @Override
    public SampleResult runTest(JavaSamplerContext context) {
        SampleResult result = new SampleResult();
        result.setSampleLabel("AES-GCM " + operation);
        try {
            result.sampleStart();
            
            if ("encrypt".equalsIgnoreCase(operation)) {
                String encryptedData = encrypt(randomData);
                
                result.setResponseData(encryptedData, "UTF-8");
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                // First encrypt the data
                String encryptedData = encrypt(randomData);
                // Then decrypt it for the benchmark
                String decryptedData = decrypt(encryptedData);
                result.setResponseData(decryptedData, "UTF-8");
            }

            result.setResponseCodeOK();
            result.setResponseMessage("OK");
            result.setSuccessful(true);
            
        } catch (Exception e) {
            result.setResponseCode("500");
            result.setResponseMessage("Error: " + e.getMessage());
            result.setSuccessful(false);
            e.printStackTrace();
        } finally {
            result.sampleEnd();
        }
        
        return result;
    }

    private String encrypt(byte[] plainText) throws Exception {

        random.nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encryptedData = cipher.doFinal(plainText);
        
        // Combine IV and encrypted data for decryption later
        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }

    private String decrypt(String encryptedText) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(encryptedText);
        
        // Extract IV and cipher text
        byte[] extractedIV = new byte[GCM_IV_LENGTH];
        byte[] cipherText = new byte[decodedData.length - GCM_IV_LENGTH];
        
        System.arraycopy(decodedData, 0, extractedIV, 0, extractedIV.length);
        System.arraycopy(decodedData, extractedIV.length, cipherText, 0, cipherText.length);
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, extractedIV);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decryptedData = cipher.doFinal(cipherText);
        
        return new String(decryptedData);
    }
}
