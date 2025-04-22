package ibm.jceplus.jmeter;
/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

import java.security.AlgorithmParameters;
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
 * JMeter benchmark for AES/GCM.
 */
public class AESGCMBenchmark extends AbstractJavaSamplerClient {

    private static final int KEY_SIZE = 256;
    private SecretKey secretKey;
    private AlgorithmParameters algP;
    private byte[] cipherText;
    private byte[] plainText;
    private int dataSize;
    private String operation;
    private Cipher cipher = null;
    private Random random = new Random(); // Use pseudo random this is good enough for data.
    private String provider;
    private int threads;
    private int loops;

    @Override
    public void setupTest(JavaSamplerContext context) {
        operation = context.getParameter("operation");
        dataSize = Integer.parseInt(context.getParameter("dataSize"));
        provider = context.getParameter("provider");
        loops = Integer.parseInt(context.getParameter("loops"));
        threads = Integer.parseInt(context.getParameter("threads"));

        try {
            // TODO Move this to utilities class....
            // Insert provider into provider list.
            if (provider.equalsIgnoreCase("OpenJCEPlus")) {
                Provider myProvider = java.security.Security.getProvider("OpenJCEPlus");
                if (myProvider == null) {
                    myProvider = (Provider) Class
                            .forName("com.ibm.crypto.plus.provider.OpenJCEPlus")
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

            // Instantiate the Cipher.
            cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);

            // Generate AES key.
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
            keyGen.init(KEY_SIZE);
            secretKey = keyGen.generateKey();

            // Generate clear plain random data.
            plainText = new byte[dataSize];
            random.nextBytes(plainText);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    @Override
    public SampleResult runTest(JavaSamplerContext context) {
        SampleResult result = new SampleResult();
        result.setSampleLabel(
            "AES/GCM Benchmark" + "\nOperation:" + operation + "\nDataSize:" + dataSize
            + "\nProvider:" + provider + "\nThreads:" + threads);

        if (!(("encrypt".equalsIgnoreCase(operation)
                || ("encryptdecrypt".equalsIgnoreCase(operation))))) {
            throw new RuntimeException("Operation value is incorrect: " + operation);
        }

        try {
            result.sampleStart();
            for (int x = 0; x <= loops; x++) {
                if ("encrypt".equalsIgnoreCase(operation)) {
                    encrypt();
                } else if ("encryptdecrypt".equalsIgnoreCase(operation)) {
                    encrypt();
                    decrypt();
                }
            }
            result.sampleEnd();

            // Set some accounting stats.
            if ("encrypt".equalsIgnoreCase(operation)) {
                result.setBytes((long) loops * dataSize);
            } else if ("encryptdecrypt".equalsIgnoreCase(operation)) {
                result.setBytes((long) loops * dataSize * 2);
            }

            result.setResponseCodeOK();
            result.setResponseMessage("OK");
            result.setSuccessful(true);
            JMeterContextService.getContext().getVariables().put("provider",provider);
            JMeterContextService.getContext().getVariables().put("operation",operation);
            JMeterContextService.getContext().getVariables().put("datasize",Integer.valueOf(dataSize).toString());
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
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        algP = cipher.getParameters();
        cipherText = cipher.doFinal(plainText);
        return cipherText;
    }

    private byte[] decrypt() throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algP);
        return cipher.doFinal(cipherText);
    }
}
