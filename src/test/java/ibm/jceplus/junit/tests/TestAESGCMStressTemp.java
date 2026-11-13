/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import ibm.jceplus.junit.tests.parameters.resolvers.AESKeySizeListParameterResolver;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * TEMPORARY - not for commit.
 *
 * Loops AES-GCM operations that overrun native buffers when the buffer size fixes in
 * GCMCipher / GCM.c are not present, while churning the Java heap and forcing GCs so that
 * corruption of adjacent heap objects is likely to turn into a crash or a wrong result.
 *
 * Duration:  -Dgcm.stress.seconds=600  (default 600)
 * Threads:   -Dgcm.stress.threads=4    (default 4)
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(AESKeySizeListParameterResolver.class)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#keySizesAndProviders")
public class TestAESGCMStressTemp extends BaseTest {

    @Parameter(0)
    int keysize;

    @Parameter(1)
    TestProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        setKeySize(keysize);
        setAndInsertProvider(provider);
    }

    @Test
    public void stressTruncatedTagsAndBoundaries() throws Exception {
        final long seconds = Long.getLong("gcm.stress.seconds", 600L);
        final int threads = Integer.getInteger("gcm.stress.threads", 4);
        // Each parameterized run (one per key size / provider) gets an equal slice
        final long deadline = System.nanoTime() + seconds * 1_000_000_000L;
        final String providerName = getProviderName();
        final int keyLen = keysize / 8;
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final long[] iterations = new long[threads];

        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int id = t;
            Thread th = new Thread(() -> {
                try {
                    iterations[id] = work(providerName, keyLen, deadline, failure, id);
                } catch (Throwable e) {
                    failure.compareAndSet(null, e);
                }
            }, "gcm-stress-" + t);
            workers.add(th);
            th.start();
        }
        for (Thread th : workers) {
            th.join();
        }
        long total = 0;
        for (long n : iterations) {
            total += n;
        }
        System.out.println("GCM stress keyLen=" + keyLen + " provider=" + providerName
                + " iterations=" + total);
        if (failure.get() != null) {
            fail("GCM stress failed: " + failure.get(), failure.get());
        }
    }

    private long work(String providerName, int keyLen, long deadline,
            AtomicReference<Throwable> failure, int id) throws Exception {
        final int[] tagBits = {96, 104, 112, 120};
        // iv + aad + key close to 1024 so the tag lands at/after the end of the
        // parameter buffer, plus a few ordinary sizes.
        final int ivLen = 12;
        final int boundaryAad = 1024 - ivLen - keyLen;
        final int[] aadLens = {0, 13, boundaryAad - 16, boundaryAad - 12, boundaryAad - 8,
                boundaryAad - 4, boundaryAad, boundaryAad + 4};
        final int[] textLens = {0, 1, 15, 16, 17, 100, 1000, 4096, 4097, 9000};

        byte[] key = new byte[keyLen];
        byte[] iv = new byte[ivLen];
        java.util.Random rnd = new java.util.Random(id);
        rnd.nextBytes(key);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        // Ring of live small arrays; native overruns hit neighbours of the tag arrays
        // allocated inside GCMCipher, so we want lots of live neighbours with data.
        byte[][] ring = new byte[4096][];
        long n = 0;

        while (System.nanoTime() < deadline && failure.get() == null) {
            int tagBit = tagBits[(int) (n % tagBits.length)];
            int aadLen = aadLens[(int) ((n / tagBits.length) % aadLens.length)];
            int textLen = textLens[(int) ((n / 3) % textLens.length)];
            if (aadLen < 0) {
                aadLen = 0;
            }

            rnd.nextBytes(iv);
            byte[] aad = new byte[aadLen];
            byte[] plain = new byte[textLen];
            rnd.nextBytes(aad);
            rnd.nextBytes(plain);
            GCMParameterSpec spec = new GCMParameterSpec(tagBit, iv);

            // churn: fill neighbouring heap with recognisable data
            for (int i = 0; i < 64; i++) {
                byte[] b = new byte[8 + rnd.nextInt(24)];
                Arrays.fill(b, (byte) 0xA5);
                ring[rnd.nextInt(ring.length)] = b;
            }

            // one shot, no previous update -> doGCMFinal_Encrypt
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            enc.init(Cipher.ENCRYPT_MODE, keySpec, spec);
            enc.updateAAD(aad);
            byte[] ct = enc.doFinal(plain);

            // update + doFinal -> do_GCM_FinalForUpdateEncrypt (heap tag array)
            Cipher enc2 = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            enc2.init(Cipher.ENCRYPT_MODE, keySpec, spec);
            enc2.updateAAD(aad);
            byte[] out2 = new byte[enc2.getOutputSize(textLen)];
            int half = textLen / 2;
            int w = enc2.update(plain, 0, half, out2, 0);
            w += enc2.doFinal(plain, half, textLen - half, out2, w);
            if (!Arrays.equals(ct, Arrays.copyOf(out2, w))) {
                throw new AssertionError("One shot and update encrypt differ: keyLen=" + keyLen
                        + " tagBit=" + tagBit + " aadLen=" + aadLen + " textLen=" + textLen);
            }

            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", providerName);
            dec.init(Cipher.DECRYPT_MODE, keySpec, spec);
            dec.updateAAD(aad);
            byte[] pt = dec.doFinal(ct);
            if (!Arrays.equals(plain, pt)) {
                throw new AssertionError("Round trip mismatch: keyLen=" + keyLen + " tagBit="
                        + tagBit + " aadLen=" + aadLen + " textLen=" + textLen);
            }

            // verify heap neighbours were not scribbled on
            for (byte[] b : ring) {
                if (b == null) {
                    continue;
                }
                for (byte x : b) {
                    if (x != (byte) 0xA5) {
                        throw new AssertionError("Heap array corrupted by native overrun");
                    }
                }
            }

            n++;
            if ((n & 0x3FF) == 0) {
                System.gc();
            }
        }
        return n;
    }
}
