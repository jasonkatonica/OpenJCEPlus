/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeOCKImplementation.h"
#include "Utils.h"
#include <stdint.h>
#include <string.h>

/* Iteration 4: Compiler hints for optimization */
#ifdef __GNUC__
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define INLINE      __attribute__((always_inline)) inline
#define NOINLINE    __attribute__((noinline))
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#define INLINE      inline
#define NOINLINE
#endif

/* Iteration 5: Optimized memory operations - reduced threshold */
static INLINE void fast_memcpy(void *dest, const void *src, size_t n) {
    /* Iteration 5: Reduced threshold to 32 - memcpy is highly optimized by compiler
     * Manual loop only beneficial for very small copies (secrets are 32 bytes) */
    if (n <= 32) {
        unsigned char *d = (unsigned char *)dest;
        const unsigned char *s = (const unsigned char *)src;
        while (n--) {
            *d++ = *s++;
        }
    } else {
        memcpy(dest, src, n);
    }
}

/* Iteration 4: Fast zero for security-sensitive buffers */
static INLINE void secure_zero(void *ptr, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (n--) {
        *p++ = 0;
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeOCKImplementation
 * Method:    KEM_encapsulate
 * Signature: (JJ[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeOCKImplementation_KEM_1encapsulate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray wrappedKey, jbyteArray randomKey) {
    
    ICC_CTX          *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY_CTX *evp_pk          = NULL;
    ICC_EVP_PKEY     *pa              = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    size_t            wrappedkeylen   = 0;
    size_t            genkeylen       = 0;
    unsigned char    *wrappedKeyLocal = NULL;
    unsigned char    *genkeylocal     = NULL;
    jbyte            *wrappedKeyBytes = NULL;
    jbyte            *randomKeyBytes  = NULL;
    int               rc              = ICC_OSSL_SUCCESS;

    /* Iteration 4: Create context once - optimized path */
    evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
    if (UNLIKELY(!evp_pk)) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return;
    }

    /* Iteration 4: Initialize encapsulation - fast path */
    rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate_init failed");
        return;
    }

    /* Iteration 4: Get required buffer sizes - optimized */
    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL,
                                  &genkeylen);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_encapsulate failed getting lengths");
        return;
    }

    /* Iteration 5: Get Java arrays with direct access BEFORE encapsulation */
    /* This eliminates intermediate buffer allocation and copy overhead */
    wrappedKeyBytes = (*env)->GetPrimitiveArrayCritical(env, wrappedKey, NULL);
    if (UNLIKELY(wrappedKeyBytes == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        return;
    }

    randomKeyBytes = (*env)->GetPrimitiveArrayCritical(env, randomKey, NULL);
    if (UNLIKELY(randomKeyBytes == NULL)) {
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyBytes, JNI_ABORT);
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        return;
    }

    /* Iteration 5: Perform encapsulation directly into Java arrays - hot path */
    /* This eliminates malloc, alignment overhead, and memcpy operations */
    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, (unsigned char *)wrappedKeyBytes,
                                  &wrappedkeylen, (unsigned char *)randomKeyBytes, &genkeylen);

    /* Iteration 5: Release arrays and cleanup */
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, randomKeyBytes, 
                                          (rc == ICC_OSSL_SUCCESS) ? 0 : JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyBytes,
                                          (rc == ICC_OSSL_SUCCESS) ? 0 : JNI_ABORT);

    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate failed");
        return;
    }
    ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeOCKImplementation
 * Method:    KEM_decapsulate
 * Signature: (JJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeOCKImplementation_KEM_1decapsulate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray wrappedKey) {
    
    ICC_CTX          *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY     *ockPKey          = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    ICC_EVP_PKEY_CTX *evp_pk           = NULL;
    int               rc               = -1;
    jboolean          isCopy           = 0;
    jbyteArray        randomKey        = NULL;
    jbyteArray        retRndKeyBytes   = NULL;
    size_t            wrappedkeylen    = 0;
    size_t            genkeylen        = 0;
    unsigned char    *wrappedKeyNative = NULL;
    unsigned char    *genkeylocal      = NULL;
    unsigned char    *genKeyNative     = NULL;

    /* Iteration 4: Create context - optimized path */
    evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
    if (UNLIKELY(!evp_pk)) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return retRndKeyBytes;
    }

    /* Iteration 4: Initialize decapsulation - fast path */
    rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate_init failed");
        return retRndKeyBytes;
    }

    /* Iteration 4: Get wrapped key with direct access */
    wrappedKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, wrappedKey, &isCopy));
    if (UNLIKELY(NULL == wrappedKeyNative)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
        return retRndKeyBytes;
    }

    wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

    /* Iteration 5: Get required buffer size for secret */
    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, NULL, &genkeylen, NULL,
                                  wrappedkeylen);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                              JNI_ABORT);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_decapsulate to get lengths failed");
        return retRndKeyBytes;
    }

    /* Iteration 5: Create result array BEFORE decapsulation */
    randomKey = (*env)->NewByteArray(env, genkeylen);
    if (UNLIKELY(randomKey == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                              wrappedKeyNative, JNI_ABORT);
        throwOCKException(env, 0, "NewByteArray failed");
        return retRndKeyBytes;
    }

    /* Iteration 5: Get direct access to result array */
    genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, randomKey, &isCopy));
    if (UNLIKELY(genKeyNative == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                              wrappedKeyNative, JNI_ABORT);
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
        return retRndKeyBytes;
    }

    /* Iteration 5: Perform decapsulation directly into Java array - hot path */
    /* This eliminates malloc, alignment overhead, and memcpy operations */
    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genKeyNative, &genkeylen,
                                  wrappedKeyNative, wrappedkeylen);

    /* Iteration 5: Release arrays */
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative,
                                          (rc == ICC_OSSL_SUCCESS) ? 0 : JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                          JNI_ABORT);

    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate failed");
        return retRndKeyBytes;
    }

    retRndKeyBytes = randomKey;
    ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);

    return retRndKeyBytes;
}