/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestDH;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestDH extends BaseTestDH {

    static {
        Utils.loadProviderTestSuite();
    }

    public TestDH() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
        isMulti = true;
    }

    public void testDH() throws Exception {
        System.out.println("executing testDH");
        BaseTestDH bt = new BaseTestDH(providerName);
        bt.run();
    }
}

