/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import junit.framework.TestCase;

public class BaseTest extends TestCase {
    //--------------------------------------------------------------------------
    //
    //
    protected String providerName;

    public BaseTest() {
        super();
    }

    //--------------------------------------------------------------------------
    //
    //
    public BaseTest(String providerName) {
        this.providerName = providerName;
    }

    /**
     * Sets the provider name that is to be used to execute this test.
     * 
     * @param providerName the provider name associated with this test case for use.
     */
    public void setProviderName(String providerName) {
        System.out.println("SETTING PROVIDER NAME!! " + providerName);
        this.providerName = providerName;
    }

    /**
     * Gets the provider name that is to be used to execute this test.
     * 
     * @return The provider name associated with this test case for use.
     */
    public String getProviderName() {
        return this.providerName;
    }
}

