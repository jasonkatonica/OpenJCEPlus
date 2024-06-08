/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import static org.junit.Assert.assertTrue;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class BaseTestSignatureJunit5  extends BaseTestJunit5 {

    protected void doSignVerify(String sigAlgo, byte[] message, PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, providerName);
        signing.initSign(privateKey);
        signing.update(message);
        byte[] signedBytes = signing.sign();

        Signature verifying = Signature.getInstance(sigAlgo, providerName);
        verifying.initVerify(publicKey);
        verifying.update(message);

        assertTrue("Signature verification failed", verifying.verify(signedBytes));
    }
}

