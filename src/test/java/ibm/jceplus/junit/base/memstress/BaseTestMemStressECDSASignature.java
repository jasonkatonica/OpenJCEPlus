/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5Signature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BaseTestMemStressECDSASignature extends BaseTestJunit5Signature {
    int numTimes = 100;
    boolean printheapstats = false;

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    String algo = "SHA256withECDSA";

    int curveSize = 256;

    @BeforeEach
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing ECDSASignature");
    }

    @Test
    public void testECDSA() throws Exception {
        KeyPair keyPair = generateKeyPair(this.curveSize);
        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            doSignVerify(this.algo, origMsg, keyPair.getPrivate(), keyPair.getPublic());
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("ECDSASignature " + this.algo + "curvesize = " + curveSize
                            + " Iteration = " + i + " " + "Total: = " + currentTotalMemory + " "
                            + "currentUsed: = " + currentUsedMemory + " " + "freeMemory: "
                            + currentFreeMemory + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }

        }
    }

    private KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance("EC", getProviderName());
        ecKeyPairGen.initialize(keysize);
        return ecKeyPairGen.generateKeyPair();
    }
}
