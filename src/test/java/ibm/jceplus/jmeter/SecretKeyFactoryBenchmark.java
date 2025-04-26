/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmeter;

import java.security.Provider;
import java.security.spec.KeySpec;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.threads.JMeterContextService;

/**
 * JMeter benchmark for SecretKeyFactory algorithms.
 */
public class SecretKeyFactoryBenchmark extends AbstractJavaSamplerClient {

    private SecretKeyFactory secretKeyFactory;
    private char[] password;
    private byte[] salt;
    private byte[] rawKeyData;
    private int iterations;
    private int keyLength;
    private String algorithm;
    private String provider;
    private String keyType;
    private int threads;
    private int loops;
    private Random random = new Random();
    private String osName = null;
    private String osArch = null;
    private String javaVersion = null;


    @Override
    public void setupTest(JavaSamplerContext context) {
        algorithm = context.getParameter("algorithm", "PBKDF2WithHmacSHA256");
        iterations = Integer.parseInt(context.getParameter("iterations", "10000"));
        keyLength = Integer.parseInt(context.getParameter("keyLength", "256"));
        provider = context.getParameter("provider", "");
        keyType = context.getParameter("keyType", "PBE").toUpperCase();
        loops = Integer.parseInt(context.getParameter("loops", "5"));
        threads = Integer.parseInt(context.getParameter("threads", "1"));
        osArch = System.getProperty("os.arch");
        osName = System.getProperty("os.name");
        javaVersion = System.getProperty("java.runtime.version");

        try {
            setupProvider();

            if (provider != null && !provider.isEmpty()) {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithm, provider);
            } else {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            }

            // Generate random password
            String passwordStr = generateRandomString(12);
            password = passwordStr.toCharArray();

            // Generate random salt
            salt = new byte[16];
            random.nextBytes(salt);

            // Generate raw key data for non-PBE algorithms
            rawKeyData = new byte[keyLength / 8];
            random.nextBytes(rawKeyData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String generateRandomString(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(characters.charAt(random.nextInt(characters.length())));
        }
        return sb.toString();
    }

    private void setupProvider() throws Exception {
        // Insert provider into provider list
        if (provider.equalsIgnoreCase("OpenJCEPlus")) {
            Provider myProvider = java.security.Security.getProvider("OpenJCEPlus");
            if (myProvider == null) {
                myProvider = (Provider) Class.forName("com.ibm.crypto.plus.provider.OpenJCEPlus")
                        .getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(myProvider, 1);
        } else if (provider.equalsIgnoreCase("BC")) {
            Provider myProvider = java.security.Security.getProvider("BC");
            if (myProvider == null) {
                myProvider = (Provider) Class
                        .forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                        .getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(myProvider, 1);
        }
    }

    @Override
    public SampleResult runTest(JavaSamplerContext context) {
        SampleResult result = new SampleResult();
        result.setSampleLabel("SecretKeyFactoryBenchmark" + " Algorithm:" + algorithm + ", KeyType:"
                + keyType + ", Iterations:" + iterations + ", KeyLength:" + keyLength
                + ", Provider:" + provider + ", Threads:" + threads);

        try {
            SecretKey secretKey = null;
            KeySpec spec = null;
            result.sampleStart();

            for (int x = 0; x < loops; x++) {
                switch (keyType) {
                    case "PBE":
                    case "PBKDF2":
                        // For PBE/PBKDF2 algorithms
                        spec = new PBEKeySpec(password, salt, iterations, keyLength);
                        break;
                    case "RAW":
                        // For raw key conversion algorithms like DES, AES, etc.
                        spec = new SecretKeySpec(rawKeyData, algorithm.split("/")[0]);
                        break;
                    default:
                        // Default to PBE
                        spec = new PBEKeySpec(password, salt, iterations, keyLength);
                }

                secretKey = secretKeyFactory.generateSecret(spec);
            }

            result.sampleEnd();

            // Using key length as bytes measurement
            result.setBytes((long) loops * keyLength / 8);
            result.setResponseCodeOK();
            result.setResponseMessage("OK");
            result.setSuccessful(true);

            JMeterContextService.getContext().getVariables().put("provider", provider);
            JMeterContextService.getContext().getVariables().put("algorithm", algorithm);
            JMeterContextService.getContext().getVariables().put("keyType", keyType);
            JMeterContextService.getContext().getVariables().put("iterations", Integer.valueOf(iterations).toString());
            JMeterContextService.getContext().getVariables().put("keyLength", Integer.valueOf(keyLength).toString());
            JMeterContextService.getContext().getVariables().put("osname", osName);
            JMeterContextService.getContext().getVariables().put("osarch", osArch);
            JMeterContextService.getContext().getVariables().put("javaruntimeversion", javaVersion);
        } catch (Exception e) {
            result.sampleEnd();
            result.setResponseCode("500");
            result.setResponseMessage("Error: " + e.getMessage());
            result.setSuccessful(false);
            e.printStackTrace();
        }
        return result;
    }
}
