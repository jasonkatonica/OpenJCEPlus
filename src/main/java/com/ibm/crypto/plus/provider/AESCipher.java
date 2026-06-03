/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.Padding;
import com.ibm.crypto.plus.provider.base.SymmetricCipher;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public final class AESCipher extends CipherSpi implements AESConstants {

    private OpenJCEPlusProvider provider = null;
    private SymmetricCipher symmetricCipher = null;
    private String mode = "ECB";
    private Padding padding = Padding.PKCS5Padding;
    private byte[] iv = null;
    private boolean encrypting = true;
    private boolean initialized = false;
    private int buffered = 0;
    private byte[] buffer = null;
    private boolean use_z_fast_command;
    private static int isHardwareSupport = 0;
    private SecureRandom cryptoRandom = null;

    public AESCipher(OpenJCEPlusProvider provider) {
        buffer = new byte[engineGetBlockSize() * 3];
        this.provider = provider;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];
            int outputLen = engineDoFinal(input, inputOffset, inputLen, output, 0);

            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (BadPaddingException | IllegalBlockSizeException bpe) {
            throw bpe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            int outputSize = engineGetOutputSize(inputLen);
            if ((output == null) || ((output.length - outputOffset) < outputSize)) {
                throw new ShortBufferException(
                        "Output buffer must be " + "(at least) " + outputSize + " bytes long");
            }

            // Common case first: standard path
            if (!use_z_fast_command) {
                return symmetricCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
            }
            
            // Z hardware fast path
            return engineDoFinalZFast(input, inputOffset, inputLen, output, outputOffset);
        } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException exc) {
            throw exc;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }
    
    // JIT-friendly: Extracted z-hardware doFinal for better optimization
    private final int engineDoFinalZFast(byte[] input, int inputOffset, int inputLen, 
            byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        // Process any remaining input
        int encryptedData = engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        outputOffset += encryptedData;
        
        // Process final block with padding
        int totalLen = processFinalBlock(output, outputOffset);
        
        buffered = 0;
        return encryptedData + totalLen;
    }
    
    // JIT-friendly: Process final block with padding
    private final int processFinalBlock(byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int totalLen = buffered;
        int paddedLen = totalLen;
        
        // Common case: encrypting with padding
        if (encrypting && padding != Padding.NoPadding) {
            int paddingLen = 16 - (totalLen % 16);
            paddedLen += paddingLen;
            padWithLen(buffer, totalLen, paddingLen);
        }

        // Validate output buffer
        if ((output == null) || (((output.length - outputOffset) < paddedLen)
                && (encrypting || padding == Padding.NoPadding))) {
            throw new ShortBufferException(
                    "Output buffer too short: " + (output.length - outputOffset)
                            + " bytes given, " + paddedLen + " bytes needed");
        }

        // Validate block size
        if (paddedLen % 16 != 0) {
            String msg = (padding == Padding.PKCS5Padding) 
                    ? "Input length (with padding) not multiple of 16 bytes"
                    : "Input length not multiple of 16 bytes";
            throw new IllegalBlockSizeException(msg);
        }

        // Process final block
        if (paddedLen == 0) {
            totalLen = 0;
        } else {
            totalLen = symmetricCipher.z_doFinal(buffer, 0, paddedLen, output, outputOffset);
        }
        
        symmetricCipher.resetParams();

        // Common case: decrypting with padding - remove padding
        if (!encrypting && padding != Padding.NoPadding) {
            int padStart = unpad(output, outputOffset, totalLen);
            if (padStart < 0) {
                throw new BadPaddingException("Given final block not properly padded");
            }
            totalLen = padStart - outputOffset;

            if ((output.length - outputOffset) < totalLen) {
                throw new ShortBufferException(
                        "Output buffer too short: " + (output.length - outputOffset)
                                + " bytes given, " + totalLen + " bytes needed");
            }
        }
        
        return totalLen;
    }

    @Override
    protected int engineGetBlockSize() {
        return AES_BLOCK_SIZE;
    }

    @Override
    protected byte[] engineGetIV() {
        return (this.iv == null) ? null : this.iv.clone();
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (!AESUtils.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + encoded.length + " bytes");
        }
        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        try {
            if (use_z_fast_command) {
                return getOutputSizeForZ(inputLen);
            } else {
                return symmetricCipher.getOutputSize(inputLen);
            }
        } catch (Exception e) {
            throw provider.providerException("Unable to get output size", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;

        if (this.iv != null) {
            IvParameterSpec ivSpec = new IvParameterSpec(this.iv);
            try {
                params = AlgorithmParameters.getInstance("AES", provider);
                params.init(ivSpec);
            } catch (NoSuchAlgorithmException nsae) {
                throw new ProviderException("Cannot find AES AlgorithmParameters implementation in "
                        + provider.getName() + " provider");
            } catch (InvalidParameterSpecException ipse) {
                // should never happen
                throw new ProviderException(ivSpec.getClass() + " not supported");
            }
        }

        return params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (mode.equals("ECB")) {
            internalInit(opmode, key, null);
            return;
        }

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            throw new InvalidKeyException("Parameters missing");
        }

        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
        byte[] generatedIv = new byte[AES_BLOCK_SIZE];
        cryptoRandom.nextBytes(generatedIv);

        internalInit(opmode, key, generatedIv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            if (params instanceof IvParameterSpec) {
                byte[] iv = ((IvParameterSpec) params).getIV();
                if (iv.length != AES_BLOCK_SIZE) {
                    throw new InvalidAlgorithmParameterException(
                            "IV must be " + AES_BLOCK_SIZE + " bytes");
                }
                internalInit(opmode, key, iv);
            } else {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        IvParameterSpec ivSpec = null;

        if (params != null) {
            try {
                ivSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }
        }

        engineInit(opmode, key, ivSpec, random);
    }

    private void internalInit(int opmode, Key key, byte[] iv) throws InvalidKeyException {
        buffered = 0;
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("AES"))) {
            throw new InvalidKeyException("Wrong algorithm: AES required");
        }

        if (!(key.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (!AESUtils.isKeySizeValid(rawKey.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + rawKey.length + " bytes");
        }

        try {
            if ((symmetricCipher == null) || (symmetricCipher.getKeyLength() != rawKey.length)) {
                symmetricCipher = SymmetricCipher.getInstanceAES(mode,
                        padding, rawKey.length, provider);
                // Check whether used algorithm is CBC and whether hardware supports is available
                use_z_fast_command = symmetricCipher.getHardwareSupportStatus();
            }

            boolean isEncrypt = (opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE);
            if (isEncrypt) {
                symmetricCipher.initCipherEncrypt(rawKey, iv);
            } else {
                symmetricCipher.initCipherDecrypt(rawKey, iv);
            }

            this.iv = iv;
            this.encrypting = isEncrypt;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String modeUpperCase = mode.toUpperCase();
        if (modeUpperCase.equals("CFB8") || modeUpperCase.equals("ECB")
                || modeUpperCase.equals("CBC") || modeUpperCase.equals("CTR")
                || modeUpperCase.equals("OFB") || modeUpperCase.equals("CFB")) {
            this.mode = modeUpperCase;
        } else if (modeUpperCase.equals("CFB128")) {
            this.mode = "CFB";
        } else {
            throw new NoSuchAlgorithmException("Cipher mode: " + mode + " not found");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("NoPadding")) {
            this.padding = Padding.NoPadding;
        } else if (padding.equalsIgnoreCase("PKCS5Padding")) {
            this.padding = Padding.PKCS5Padding;
        } else {
            throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkCipherInitialized();

        try {
            byte[] output = null;
            int outputLen = -1;
            if (use_z_fast_command) {
                output = new byte[getOutputSizeForZ(inputLen)];
                outputLen = engineUpdate(input, inputOffset, inputLen, output, 0);
            } else {
                output = new byte[engineGetOutputSize(inputLen)];
                outputLen = symmetricCipher.update(input, inputOffset, inputLen, output, 0);
            }
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        checkCipherInitialized();

        try {
            // Common case first: use standard path
            if (!use_z_fast_command) {
                return symmetricCipher.update(input, inputOffset, inputLen, output, outputOffset);
            }
            
            // Fast path for z hardware
            return engineUpdateZFast(input, inputOffset, inputLen, output, outputOffset);
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }
    
    // JIT-friendly: Extracted z-hardware fast path for better optimization
    private final int engineUpdateZFast(byte[] input, int inputOffset, int inputLen, 
            byte[] output, int outputOffset) throws ShortBufferException {
        // Early return for empty input
        if (input == null || inputLen == 0) {
            return 0;
        }

        // Calculate processable length
        int len = calculateProcessableLength(inputLen);

        // Validate output buffer
        validateOutputBuffer(output, outputOffset, len);

        if (len == 0) {
            // Just buffer the input
            System.arraycopy(input, inputOffset, buffer, buffered, inputLen);
            buffered += inputLen;
            return 0;
        }

        // Process buffered and input data
        int bytesProcessed = processBufferedAndInput(input, inputOffset, inputLen, 
                output, outputOffset, len);
        
        return bytesProcessed;
    }
    
    // JIT-friendly: Small helper for length calculation
    private final int calculateProcessableLength(int inputLen) {
        int len = buffered + inputLen;
        // Common case: encrypting or no padding
        if (encrypting || padding != Padding.PKCS5Padding) {
            return (len > 0) ? (len - (len % 16)) : 0;
        }
        // Decrypting with padding: reserve last block
        len -= 16;
        return (len > 0) ? (len - (len % 16)) : 0;
    }
    
    // JIT-friendly: Small validation method
    private final void validateOutputBuffer(byte[] output, int outputOffset, int len) 
            throws ShortBufferException {
        if ((output == null) || ((output.length - outputOffset) < len)) {
            throw new ShortBufferException(
                    "Output buffer must be " + "(at least) " + len + " bytes long");
        }
    }
    
    // JIT-friendly: Process buffered and input data
    private final int processBufferedAndInput(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset, int targetLen) throws ShortBufferException {
        int inputConsumed = targetLen - buffered;
        int bufferedConsumed = buffered;

        // Adjust for negative consumption
        if (inputConsumed < 0) {
            inputConsumed = 0;
            bufferedConsumed = targetLen;
        }

        int totalProcessed = 0;

        // Process buffered data
        if (bufferedConsumed > 0) {
            totalProcessed = processBufferedData(input, inputOffset, inputConsumed, 
                    bufferedConsumed, output, outputOffset);
            outputOffset += bufferedConsumed;
            
            // Update input tracking
            int remainToUnit = (inputConsumed > 0) ? (inputConsumed % 16) : 0;
            inputOffset += remainToUnit;
            inputLen -= remainToUnit;
            inputConsumed -= remainToUnit;
        }

        // Process bulk input data
        if (inputConsumed > 0) {
            totalProcessed += symmetricCipher.z_update(input, inputOffset, inputConsumed, 
                    output, outputOffset);
            inputLen -= inputConsumed;
            inputOffset += inputConsumed;
        }

        // Buffer remaining input
        if (inputLen > 0) {
            System.arraycopy(input, inputOffset, buffer, buffered, inputLen);
        }
        buffered += inputLen;

        return totalProcessed;
    }
    
    // JIT-friendly: Process buffered data with alignment
    private final int processBufferedData(byte[] input, int inputOffset, int inputConsumed,
            int bufferedConsumed, byte[] output, int outputOffset) throws ShortBufferException {
        if (inputConsumed > 0) {
            // Align buffer to block boundary
            int remainToUnit = inputConsumed % 16;
            System.arraycopy(input, inputOffset, buffer, bufferedConsumed, remainToUnit);
            bufferedConsumed += remainToUnit;
            buffered += remainToUnit;
        }

        int processed = symmetricCipher.z_update(buffer, 0, bufferedConsumed, output, outputOffset);
        buffered -= bufferedConsumed;

        // Shift remaining buffer data
        if (buffered > 0) {
            System.arraycopy(buffer, bufferedConsumed, buffer, 0, buffered);
        }

        return processed;
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }

        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        checkCipherInitialized();

        try {
            byte[] encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return ConstructKeys.constructKey(provider, encoded, algorithm, type);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        } catch (IllegalBlockSizeException e) {
            // should not occur, handled with length check above
            throw new InvalidKeyException("Unwrapping failed", e);
        }
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    /**
     * Gets the expected output size from the encryption of a specific input data. Function used only on Z14 machines.
     * @param inputLen
     * @return
     */
    // JIT-friendly: Small method for guaranteed inlining
    private final int getOutputSizeForZ(int inputLen) {
        int totalLen = Math.addExact(buffered, inputLen);
        // Common case first for better branch prediction
        if (encrypting && padding != Padding.NoPadding) {
            return Math.addExact(totalLen, 16 - (totalLen % 16));
        }
        return totalLen;
    }

    /**
     * Helper function used only on Z14 machines.
     * @param in
     * @param off
     * @param len
     * @throws ShortBufferException
     */
    // JIT-friendly: Small, final method for inlining
    private final void padWithLen(byte[] in, int off, int len) throws ShortBufferException {
        if (in == null)
            return;

        int idx = Math.addExact(off, len);
        if (idx > in.length)
            throw new ShortBufferException("Buffer too small to hold padding");

        byte paddingOctet = (byte) (len & 0xff);
        Arrays.fill(in, off, idx, paddingOctet);
    }

    /**
     * Helper function used only on Z14 machines.
     * @param in
     * @param off
     * @param len
     * @return
     */
    // JIT-friendly: Optimized for better branch prediction and loop optimization
    private final int unpad(byte[] in, int off, int len) {
        // Common case checks first
        if ((in == null) || (len == 0)) {
            return 0;
        }
        
        int idx = Math.addExact(off, len);
        byte lastByte = in[idx - 1];
        int padValue = (int) lastByte & 0x0ff;
        
        // Range check with common case first (valid padding)
        if ((padValue >= 0x01) && (padValue <= 16)) {
            int start = idx - padValue;
            if (start >= off) {
                // Loop with loop-invariant bound for better optimization
                final int endIdx = idx;
                for (int i = start; i < endIdx; i++) {
                    if (in[i] != lastByte) {
                        return -1;
                    }
                }
                return start;
            }
        }
        return -1;
    }
}
