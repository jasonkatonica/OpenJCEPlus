/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import sun.security.internal.spec.TlsMasterSecretParameterSpec;
import sun.security.internal.spec.TlsPrfParameterSpec;
import sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;

/**
 * This test exercises the TLS 1.2 PRF key generator.
*/
public class BaseTestTLSKeyGenerators extends BaseTestJunit5 {

    private static Stream<Arguments> testParameters() {
        return Stream.of(
            Arguments.of(
            "9bbe436ba940f017b17652849a71db35",
            "a0ba9f936cda311827a6f796ffd5198c",
            "test label",
            100,
            "SHA-256",
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
            ),
            Arguments.of(
            "b80b733d6ceefcdc71566ea48e5567df",
            "cd665cf6a8447dd6ff8b27555edb7465",
            "test label",
            148,
            "SHA-384",
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f"
            ),
            Arguments.of(
            "b0323523c1853599584d88568bbb05eb",
            "d4640e12e4bcdbfb437f03e6ae418ee5",
            "test label",
            196,
            "SHA-512",
            "1261f588c798c5c201ff036e7a9cb5edcd7fe3f94c669a122a4638d7d508b283042df6789875c7147e906d868bc75c45e20eb40c1cf4a1713b27371f68432592f7dc8ea8ef223e12ea8507841311bf68653d0cfc4056d811f025c45ddfa6e6fec702f054b409d6f28dd0a3233e498da41a3e75c5630eedbe22fe254e33a1b0e9f6b9826675bec7d01a845658dc9c397545401d40b9f46c7a400ee1b8f81ca0a60d1a397a1028bff5d2ef5066126842fb8da4197632bdb54ff6633f86bbc836e640d4d898"
            )
        );
    }

    @ParameterizedTest
    @MethodSource("testParameters")
    public void testTlsSecretKeyGenerator(String prfSecret, String prfSeed, String prfLabel, int prfLength, String prfAlg, String prfOutput) throws Exception {

        System.out.println("Test " + prfAlg + ".");
        byte[] secret = BaseUtils.hexStringToByteArray(prfSecret);
        byte[] seed = BaseUtils.hexStringToByteArray(prfSeed);
        byte[] expectedOutput = BaseUtils.hexStringToByteArray(prfOutput);
        int prfHashLength = 0;
        int prfBlockSize = 0;
        SecretKey inKey = new SecretKeySpec(secret, "Generic");

        switch (prfAlg) {
            case "SHA-224":
                prfHashLength = 28;
                prfBlockSize =  64;
                break;
            case "SHA-256":
                prfHashLength = 32;
                prfBlockSize =  64;
                break;
            case "SHA-384":
                prfHashLength = 48;
                prfBlockSize = 128;
                break;
            case "SHA-512":
                prfHashLength = 64;
                prfBlockSize = 128;
                break;
            default:
                throw new Exception("Unknown prf algorithm: " + prfAlg);
        }

        KeyGenerator kg = KeyGenerator.getInstance("SunTls12Prf", getProviderName());
        @SuppressWarnings("deprecation")
        TlsPrfParameterSpec spec = new TlsPrfParameterSpec(
                                            inKey, 
                                            prfLabel,
                                            seed,
                                            prfLength,
                                            prfAlg,
                                            prfHashLength,
                                            prfBlockSize);
        kg.init(spec);
        SecretKey key = kg.generateKey();
        byte[] encoding = key.getEncoded();
        Assertions.assertArrayEquals( expectedOutput, encoding );
    }

    @Test 
    public void testTLS12KeyGeneration() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        // Generate RSA Pre-Master Secret.
        SecretKey rsaPreMasterSecret = null;
        @SuppressWarnings("deprecation")
        TlsRsaPremasterSecretParameterSpec rsaPreMasterSecretSpec =
                new TlsRsaPremasterSecretParameterSpec(0x0303, 0x0303);
        {
            KeyGenerator rsaPreMasterSecretKG = KeyGenerator.getInstance(
                    "SunTls12RsaPremasterSecret", "SunJCE");
            rsaPreMasterSecretKG.init(rsaPreMasterSecretSpec, null);
            rsaPreMasterSecret = rsaPreMasterSecretKG.generateKey();
        }
    }
}
