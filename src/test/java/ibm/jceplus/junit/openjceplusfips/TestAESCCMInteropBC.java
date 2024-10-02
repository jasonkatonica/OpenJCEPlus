/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import ibm.jceplus.junit.base.BaseTestAESCCMInteropBC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestAESCCMInteropBC extends BaseTestAESCCMInteropBC {

    @BeforeAll
    public void beforeAll() throws Exception {
        Utils.loadProviderTestSuite();
        Utils.loadProviderBC();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        setInteropProviderName(Utils.PROVIDER_BC);
    }
}
