/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.MessageDigest;
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
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
public class MessageDigestBenchmark  extends OpenJCEPlusJMHBase {

    @Param({"16", "2048", "16384"})
    private int payload;

    @Param({"OpenJCEPlus", "SUN"})
    private String provider;

    @Param({"SHA-512", "SHA-256", "MD5", "SHA1"})
    private String algorithm;

    private byte[] data;
    private MessageDigest messageDigest;

    @Setup
    public void setup() throws Exception {
        insertProvider(provider);

        data = new byte[payload];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        messageDigest = MessageDigest.getInstance(algorithm, provider);
    }

    @Benchmark
    public byte[] updateDigest() {
        messageDigest.update(data);
        return messageDigest.digest();
    }

    @Benchmark
    public byte[] singleShotDigest(Blackhole blackhole) {
        return messageDigest.digest(data);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MessageDigestBenchmark.class.getSimpleName();
        Options opt = optionsBuild(
            testSimpleName,
            testSimpleName);

        new Runner(opt).run();
    }
}
