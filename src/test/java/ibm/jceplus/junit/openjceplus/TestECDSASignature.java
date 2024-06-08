/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import ibm.jceplus.junit.base.BaseTestECDSASignature;

@TestInstance(Lifecycle.PER_CLASS)
public class TestECDSASignature extends BaseTestECDSASignature {

    @BeforeAll
    public void beforeAll() {
        try {
        System.out.println("Running beforeAll");
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
