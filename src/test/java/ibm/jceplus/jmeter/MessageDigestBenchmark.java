/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmeter;

import java.security.MessageDigest;
import java.security.Provider;
import java.util.Random;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.threads.JMeterContextService;

/**
 * JMeter benchmark for message digest algorithms.
 */
public class MessageDigestBenchmark extends AbstractJavaSamplerClient {

    private MessageDigest messageDigest;
    private byte[] inputData;
    private int dataSize;
    private String algorithm;
    private String provider;
    private int threads;
    private int loops;
    private Random random = new Random();
    private String osName = null;
    private String osArch = null;
    private String javaVersion = null;


    @Override
    public void setupTest(JavaSamplerContext context) {
        algorithm = context.getParameter("algorithm");
        dataSize = Integer.parseInt(context.getParameter("dataSize"));
        provider = context.getParameter("provider");
        loops = Integer.parseInt(context.getParameter("loops"));
        threads = Integer.parseInt(context.getParameter("threads"));
        osArch = System.getProperty("os.arch");
        osName = System.getProperty("os.name");
        javaVersion = System.getProperty("java.runtime.version");

        try {
            setupProvider();
            
            if (provider != null && !provider.isEmpty()) {
                messageDigest = MessageDigest.getInstance(algorithm, provider);
            } else {
                messageDigest = MessageDigest.getInstance(algorithm);
            }

            inputData = new byte[dataSize];
            random.nextBytes(inputData);
        } catch (Exception e) {
            e.printStackTrace();
            //System.exit(-1);
        }
    }

    private void setupProvider() throws Exception {
        // Insert provider into provider list
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
    }

    @Override
    public SampleResult runTest(JavaSamplerContext context) {
        SampleResult result = new SampleResult();
        result.setSampleLabel(
            "MessageDigestBenchmark" + " Algorithm:" + algorithm + ", DataSize:" + dataSize
            + ", Provider:" + provider + ", Threads:" + threads);

        try {
            byte[] hashResult = null;
            result.sampleStart();
            for (int x = 0; x < loops; x++) {
                messageDigest.reset();
                messageDigest.update(inputData);
                hashResult = messageDigest.digest();
            }
            
            result.sampleEnd();

            result.setBytes((long) loops * dataSize);
            result.setResponseCodeOK();
            result.setResponseMessage("OK");
            result.setSuccessful(true);
            
            JMeterContextService.getContext().getVariables().put("provider", provider);
            JMeterContextService.getContext().getVariables().put("algorithm", algorithm);
            JMeterContextService.getContext().getVariables().put("datasize", Integer.valueOf(dataSize).toString());
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