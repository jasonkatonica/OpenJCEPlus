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
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.threads.JMeterContextService;

/**
 * JMeter benchmark for SecretKeyFactory algorithms.
 */
public class SecretKeyFactoryBenchmark extends AbstractJavaSamplerClient {

    private SecretKeyFactory secretKeyFactory;
    private byte[] salt = new byte[16];
    private int iterations = 300000;
    private int keyLength = 512;
    private String algorithm;
    private String provider;
    private int threads;
    private int loops;
    private Random random = new Random();
    private String osName = null;
    private String osArch = null;
    private String javaVersion = null;
    private static final String PASSWORD = "thisisareasonablesizedpassword";

    @Override
    public void setupTest(JavaSamplerContext context) {
        algorithm = context.getParameter("algorithm");
        provider = context.getParameter("provider");
        loops = Integer.parseInt(context.getParameter("loops"));
        threads = Integer.parseInt(context.getParameter("threads"));
        osArch = System.getProperty("os.arch");
        osName = System.getProperty("os.name");
        javaVersion = System.getProperty("java.runtime.version");

        try {
            setupProvider();
            secretKeyFactory = SecretKeyFactory.getInstance(algorithm, provider);
            random.nextBytes(salt);
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

    @Override
    public SampleResult runTest(JavaSamplerContext context) {
        SampleResult result = new SampleResult();
        result.setSampleLabel("SecretKeyFactoryBenchmark" + " Algorithm:" + algorithm
                + ", Iterations:" + iterations + ", KeyLength:" + keyLength
                + ", Provider:" + provider + ", Threads:" + threads + ", " + osArch + "-" + osName);

        try {
            KeySpec spec = new PBEKeySpec(PASSWORD.toCharArray(), salt, iterations, keyLength);

            result.sampleStart();
            for (int x = 0; x < loops; x++) {
                SecretKey secretKey = secretKeyFactory.generateSecret(spec);
            }
            result.sampleEnd();

            // Using key length as bytes measurement
            result.setBytes((long) loops * keyLength);
            result.setResponseCodeOK();
            result.setResponseMessage("OK");
            result.setSuccessful(true);

            JMeterContextService.getContext().getVariables().put("provider", provider);
            JMeterContextService.getContext().getVariables().put("algorithm", algorithm);
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
