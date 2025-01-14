/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({
    TestAES_128.class,
    TestAES_192.class,
    TestAES_256.class,
    TestAES.class,
    TestAES256Interop.class,
    TestAESCCM.class,
    TestAESCCM2.class,
    TestAESCCMInteropBC.class,
    TestAESCCMParameters.class,
    TestAESCipherInputStreamExceptions.class,
    TestAESCopySafe.class,
    TestAESGCM_128.class,
    TestAESGCM_192.class,
    TestAESGCM_256.class,
    TestAESGCM_ExtIV.class,
    TestAESGCM_IntIV.class,
    TestAESGCM.class,
    TestAESGCMBufferIV.class,
    TestAESGCMCICOWithGCM.class,
    TestAESGCMCICOWithGCMAndAAD.class,
    TestAESGCMLong.class,
    TestAESGCMNonExpanding.class,
    TestAESGCMSameBuffer.class,
    TestAESGCMUpdate.class,
    TestAESGCMUpdateInteropBC.class,
    TestAESGCMWithByteBuffer.class,
    TestAliases.class,
    TestByteArrayOutputDelay.class,
    TestChaCha20.class,
    TestChaCha20KAT.class,
    TestChaCha20NoReuse.class,
    TestChaCha20Poly1305.class,
    TestChaCha20Poly1305ByteBuffer.class,
    TestChaCha20Poly1305ChunkUpdate.class,
    TestDESede.class,
    TestDH.class,
    TestDHInteropSunJCE.class,
    TestDHKeyFactory.class,
    TestDHKeyPairGenerator.class,
    TestDHMultiParty.class,
    TestDSAKey.class,
    TestDSASignature.class,
    TestDSASignatureInteropBC.class,
    TestDSASignatureInteropSUN.class,
    TestECDH.class,
    TestECDHInteropBC.class,
    TestECDHInteropSunEC.class,
    TestECDHKeyAgreementParamValidation.class,
    TestECDHMultiParty.class,
    TestECDSASignature.class,
    TestECDSASignatureInteropBC.class,
    TestECDSASignatureInteropSunEC.class,
    TestECKeyImport.class,
    TestECKeyImportInteropSunEC.class,
    TestECKeyPairGenerator.class
})

@Suite
public class TestAll {
}
