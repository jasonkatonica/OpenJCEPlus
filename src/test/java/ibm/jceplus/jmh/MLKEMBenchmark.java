/*
 * Copyright IBM Corp. 2025, 2026
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
import org.openjdk.jmh.annotations.CompilerControl;
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

/**
 * JMH Benchmark for ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism).
 * 
 * Configuration optimizations (Iteration 10):
 * - Thread-scoped state for better isolation and reduced contention
 * - Optimized warmup/measurement iterations for faster convergence
 * - Pre-cached encapsulation results to reduce setup overhead
 * - CompilerControl annotations to prevent unwanted inlining
 * - Minimized object allocation in hot paths
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)  // Changed from Benchmark to Thread for better isolation
@Warmup(iterations = 5, time = 5, timeUnit = TimeUnit.SECONDS)  // More iterations, shorter time for faster warmup
@Measurement(iterations = 5, time = 10, timeUnit = TimeUnit.SECONDS)  // More iterations, shorter time for better statistics
public class MLKEMBenchmark extends JMHBase {

    // Cache algorithm string to avoid repeated allocations
    private static final String ALGORITHM_AES = "AES";
    private static final int KEY_FROM = 0;
    private static final int KEY_SIZE = 31;

    @Param({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    private String transformation;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    // Thread-local instances for better performance
    private KEM myKEM;
    private KeyPair keyPair;
    private KEM.Encapsulator encapsulator;
    private KEM.Decapsulator decapsulator;
    
    // Pre-cached encapsulation result to avoid repeated setup
    private KEM.Encapsulated cachedEncapsulated;
    private byte[] cachedEncapsulation;

    @Setup
    public void setup() throws Exception {
        // Initialize provider (inherited from JMHBase)
        super.setup(provider);

        // Initialize KEM and key pair generator
        myKEM = KEM.getInstance(transformation, provider);
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(transformation, provider);
        
        // Generate key pair once during setup
        keyPair = keyPairGen.generateKeyPair();
        
        // Pre-initialize encapsulator and decapsulator
        encapsulator = myKEM.newEncapsulator(keyPair.getPublic());
        decapsulator = myKEM.newDecapsulator(keyPair.getPrivate());
        
        // Pre-cache an encapsulation result for decapsulation benchmark
        cachedEncapsulated = encapsulator.encapsulate(KEY_FROM, KEY_SIZE, ALGORITHM_AES);
        cachedEncapsulation = cachedEncapsulated.encapsulation();
    }

    /**
     * Benchmark encapsulation operation only.
     * CompilerControl.DONT_INLINE prevents JIT from inlining and skewing results.
     */
    @Benchmark
    @CompilerControl(CompilerControl.Mode.DONT_INLINE)
    public SecretKey encapsulation() throws Exception {
        KEM.Encapsulated result = encapsulator.encapsulate(KEY_FROM, KEY_SIZE, ALGORITHM_AES);
        return result.key();
    }

    /**
     * Benchmark decapsulation operation only.
     * Uses pre-cached encapsulation to avoid setup overhead.
     */
    @Benchmark
    @CompilerControl(CompilerControl.Mode.DONT_INLINE)
    public SecretKey decapsulation() throws Exception {
        return decapsulator.decapsulate(cachedEncapsulation, KEY_FROM, KEY_SIZE, ALGORITHM_AES);
    }

    /**
     * Benchmark full encapsulation + decapsulation cycle.
     * Measures end-to-end performance.
     */
    @Benchmark
    @CompilerControl(CompilerControl.Mode.DONT_INLINE)
    public SecretKey encapsulationAndDecapsulation() throws Exception {
        KEM.Encapsulated enc = encapsulator.encapsulate(KEY_FROM, KEY_SIZE, ALGORITHM_AES);
        return decapsulator.decapsulate(enc.encapsulation(), KEY_FROM, KEY_SIZE, ALGORITHM_AES);
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = MLKEMBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}