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
import java.util.concurrent.TimeUnit;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
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
public class MLKEMBenchmark extends OpenJCEPlusJMHBase {

    @Param({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    private String algorithm;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private KEM pqcKEM;
    private KeyPair keyPair;
    private KeyPairGenerator pqcKeyPairGen;
    private KEM.Encapsulator encr;
    private KEM.Encapsulated enc;
    private KEM.Decapsulator decr;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        pqcKEM = KEM.getInstance(algorithm, provider);
        pqcKeyPairGen = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair = pqcKeyPairGen.generateKeyPair();
        keyPair.getPublic();
        keyPair.getPrivate();
        encr = pqcKEM.newEncapsulator(keyPair.getPublic());
        enc = encr.encapsulate(0,31,"AES");
        decr = pqcKEM.newDecapsulator(keyPair.getPrivate());
    }

    @Benchmark
    public SecretKey encapsulation() throws Exception {
        enc = encr.encapsulate(0,31,"AES");
        return enc.key();
    }

    @Benchmark
    public SecretKey decapsulation() throws Exception {
        return decr.decapsulate(enc.encapsulation(),0,31,"AES");
    }

    @Benchmark
    public SecretKey encapsulationAndDecapsulation() throws Exception {
        enc = encr.encapsulate(0,31,"AES");
        return decr.decapsulate(enc.encapsulation(),0,31,"AES");
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MLKEMBenchmark.class.getSimpleName();
        Options opt = optionsBuild(
            testSimpleName,
            testSimpleName);

        new Runner(opt).run();
    }
}
