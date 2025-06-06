/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
public class MLDSABenchmark  extends OpenJCEPlusJMHBase {

    @Param({"64", "1024", "8192", "65536"})
    private int messageSize;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    @Param({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    private String pqcParameterSet;
    
    private KeyPairGenerator keyPairGenerator;
    private Signature signatureInstance;
    private Signature verifierInstance;
    private KeyPair keyPair;
    private byte[] signature;
    private byte[] message;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        keyPairGenerator = KeyPairGenerator.getInstance(pqcParameterSet, provider);
        signatureInstance = Signature.getInstance(pqcParameterSet, provider);
        verifierInstance = Signature.getInstance(pqcParameterSet, provider);

        keyPair = keyPairGenerator.generateKeyPair();
        signatureInstance.initSign(keyPair.getPrivate());
        message = new byte[messageSize];
        signatureInstance.update(message);
        signature = signatureInstance.sign();
    }

    @Benchmark
    public KeyPair keyGeneration() throws Exception {
        return keyPairGenerator.generateKeyPair();
    }

    @Benchmark
    public byte[] sign() throws Exception {
        signatureInstance.initSign(keyPair.getPrivate());
        signatureInstance.update(message);
        return signatureInstance.sign();
    }

    @Benchmark
    public boolean verify() throws Exception {
        verifierInstance.initVerify(keyPair.getPublic());
        verifierInstance.update(message);
        return verifierInstance.verify(signature);
    }

    @Benchmark
    public boolean signAndVerify() throws Exception {
        // Sign
        signatureInstance.initSign(keyPair.getPrivate());
        signatureInstance.update(message);
        byte[] sig = signatureInstance.sign();
        
        // Verify
        verifierInstance.initVerify(keyPair.getPublic());
        verifierInstance.update(message);
        return verifierInstance.verify(sig);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MLDSABenchmark.class.getSimpleName();
        Options opt = optionsBuild(
            testSimpleName,
            testSimpleName);

        new Runner(opt).run();
    }
}
