/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmeter;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.threads.JMeterContextService;

/**
 * JMeter benchmark for ciphers.
 */
public class CipherBenchmark extends AbstractJavaSamplerClient {

    private static final int AES_KEY_SIZE = 256;
    private static final int TDES_KEY_SIZE = 168;
    private static final int RSA_KEY_SIZE = 2048;
    private SecretKey secretKey;
    private KeyPair keyPair;
    private AlgorithmParameters algParams;
    private byte[] cipherText;
    private byte[] plainText;
    private int dataSize;
    private String operation;
    private String algorithm;
    private Cipher cipher = null;
    private Random random = new Random();
    private String provider;
    private int threads;
    private int loops;
    private String osName = null;
    private String osArch = null;
    private String javaVersion = null;

    @Override
    public void setupTest(JavaSamplerContext context) {
        operation = context.getParameter("operation");
        dataSize = Integer.parseInt(context.getParameter("dataSize"));
        provider = context.getParameter("provider");
        algorithm = context.getParameter("algorithm");
        loops = Integer.parseInt(context.getParameter("loops"));
        threads = Integer.parseInt(context.getParameter("threads"));
        osArch = System.getProperty("os.arch");
        osName = System.getProperty("os.name");
        javaVersion = System.getProperty("java.runtime.version");

        try {
            setupProvider();
            cipher = Cipher.getInstance(algorithm, provider);
            generateKeys();
            plainText = new byte[dataSize];
            random.nextBytes(plainText);
        } catch (Exception e) {
            e.printStackTrace();
            //System.exit(-1);
        }
    }

    private void setupProvider() throws Exception {
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

    private void generateKeys() throws Exception {
        if (algorithm.startsWith("AES")) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            secretKey = keyGen.generateKey();
        } else if (algorithm.startsWith("TDES") || algorithm.startsWith("DESede")) {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            keyGen.init(TDES_KEY_SIZE);
            secretKey = keyGen.generateKey();
        } else if (algorithm.startsWith("RSA")) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(RSA_KEY_SIZE);
            keyPair = keyGen.generateKeyPair();
        }
    }

    @Override
    public SampleResult runTest(JavaSamplerContext context) {
        SampleResult result = new SampleResult();
        result.setSampleLabel(
            "CipherBenchmark" + " Algorithm:" + algorithm + ", Operation:" + operation + ", DataSize:" + dataSize
            + ", Provider:" + provider + ", Threads:" + threads + ", " + osArch + "-" + osName);

        if (!(("encrypt".equalsIgnoreCase(operation) || ("encryptdecrypt".equalsIgnoreCase(operation))))) {
            throw new RuntimeException("Operation value is incorrect: " + operation);
        }

        try {
            result.sampleStart();
            for (int x = 0; x < loops; x++) {
                if ("encrypt".equalsIgnoreCase(operation)) {
                    encrypt();
                } else if ("encryptdecrypt".equalsIgnoreCase(operation)) {
                    encrypt();
                    decrypt();
                }
            }
            result.sampleEnd();

            if ("encrypt".equalsIgnoreCase(operation)) {
                result.setBytes((long) loops * plainText.length);
            } else if ("encryptdecrypt".equalsIgnoreCase(operation)) {
                result.setBytes((long) loops * plainText.length * 2);
            }
            result.setResponseCodeOK();
            result.setResponseMessage("OK");
            result.setSuccessful(true);

            JMeterContextService.getContext().getVariables().put("provider", provider);
            JMeterContextService.getContext().getVariables().put("algorithm", algorithm);
            JMeterContextService.getContext().getVariables().put("operation", operation);
            JMeterContextService.getContext().getVariables().put("datasize",Integer.valueOf(dataSize).toString());
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

    private byte[] encrypt() throws Exception {
        if (algorithm.startsWith("RSA")) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        algParams = cipher.getParameters();
        cipherText = cipher.doFinal(plainText);
        return cipherText;
    }

    private byte[] decrypt() throws Exception {
        if (algorithm.startsWith("RSA")) {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algParams);
        }

        return cipher.doFinal(cipherText);
    }
}
