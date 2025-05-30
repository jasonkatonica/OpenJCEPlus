/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestDESede;
import ibm.jceplus.junit.openjceplus.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestDESede extends BaseTestDESede {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    /**
     * 
     * This method is to check whether a mode is valid for the cipher
     * but not supported by a given provider.
    */
    @Override
    public boolean isModeValidButUnsupported(String mode) {
        if (mode.equalsIgnoreCase("CFB") || mode.equalsIgnoreCase("CFB64")
                || mode.equalsIgnoreCase("OFB")) {
            return true;
        }

        return super.isModeValidButUnsupported(mode);
    }
}
