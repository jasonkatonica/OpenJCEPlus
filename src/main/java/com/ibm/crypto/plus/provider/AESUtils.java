/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

class AESUtils {

    private AESUtils() {}

    static final boolean isKeySizeValid(int keySize) {
        // Optimization: Direct comparison is faster than array iteration
        // This benefits all key sizes uniformly by eliminating loop overhead
        // AES supports only 128-bit (16 bytes), 192-bit (24 bytes), and 256-bit (32 bytes)
        return keySize == 16 || keySize == 24 || keySize == 32;
    }

}
