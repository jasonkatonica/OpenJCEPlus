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

/* Iteration 4: Fast memory operations for small buffers */
static INLINE void fast_memcpy(void *dest, const void *src, size_t n) {
    /* For small buffers, direct copy is faster than memcpy */
    if (n <= 64) {
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

    /* Iteration 4: Allocate buffers with alignment for better cache performance */
    wrappedKeyLocal = (unsigned char *)malloc(wrappedkeylen + 64);
    genkeylocal     = (unsigned char *)malloc(genkeylen + 64);
    if (UNLIKELY(wrappedKeyLocal == NULL || genkeylocal == NULL)) {
        free(wrappedKeyLocal);
        free(genkeylocal);
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "malloc failed");
        return;
    }

    /* Iteration 4: Align pointers to 64-byte boundary for cache optimization */
    unsigned char *wrappedKeyAligned = (unsigned char *)(((uintptr_t)wrappedKeyLocal + 63) & ~63);
    unsigned char *genkeyAligned = (unsigned char *)(((uintptr_t)genkeylocal + 63) & ~63);

    /* Iteration 4: Perform encapsulation - hot path */
    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedKeyAligned,
                                  &wrappedkeylen, genkeyAligned, &genkeylen);

    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        secure_zero(genkeylocal, genkeylen + 64);
        free(wrappedKeyLocal);
        free(genkeylocal);
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate failed");
        return;
    }

    /* Iteration 4: Use GetPrimitiveArrayCritical for direct memory access (faster) */
    /* This locks the array in memory and provides direct pointer access */
    wrappedKeyBytes = (*env)->GetPrimitiveArrayCritical(env, wrappedKey, NULL);
    if (UNLIKELY(wrappedKeyBytes == NULL)) {
        secure_zero(genkeylocal, genkeylen + 64);
        free(wrappedKeyLocal);
        free(genkeylocal);
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        return;
    }
    
    /* Iteration 4: Fast copy for wrapped key */
    fast_memcpy(wrappedKeyBytes, wrappedKeyAligned, wrappedkeylen);
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyBytes, 0);

    /* Iteration 4: Get random key array */
    randomKeyBytes = (*env)->GetPrimitiveArrayCritical(env, randomKey, NULL);
    if (UNLIKELY(randomKeyBytes == NULL)) {
        secure_zero(genkeylocal, genkeylen + 64);
        free(wrappedKeyLocal);
        free(genkeylocal);
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        return;
    }
    
    /* Iteration 4: Fast copy for secret key */
    fast_memcpy(randomKeyBytes, genkeyAligned, genkeylen);
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, randomKeyBytes, 0);

    /* Iteration 4: Secure cleanup - zero sensitive data */
    secure_zero(genkeylocal, genkeylen + 64);
    free(wrappedKeyLocal);
    free(genkeylocal);
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

    /* Iteration 4: Get required buffer size for secret */
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

    /* Iteration 4: Allocate aligned buffer for better cache performance */
    genkeylocal = (unsigned char *)malloc(genkeylen + 64);
    if (UNLIKELY(genkeylocal == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                              JNI_ABORT);
        throwOCKException(env, 0, "malloc failed");
        return retRndKeyBytes;
    }

    /* Iteration 4: Align pointer to 64-byte boundary */
    unsigned char *genkeyAligned = (unsigned char *)(((uintptr_t)genkeylocal + 63) & ~63);

    /* Iteration 4: Perform decapsulation - hot path */
    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genkeyAligned, &genkeylen,
                                  wrappedKeyNative, wrappedkeylen);

    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        secure_zero(genkeylocal, genkeylen + 64);
        free(genkeylocal);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                              wrappedKeyNative, JNI_ABORT);
        throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate failed");
        return retRndKeyBytes;
    }

    /* Iteration 4: Create result array */
    randomKey = (*env)->NewByteArray(env, genkeylen);
    if (UNLIKELY(randomKey == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        secure_zero(genkeylocal, genkeylen + 64);
        free(genkeylocal);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                              wrappedKeyNative, JNI_ABORT);
        throwOCKException(env, 0, "NewByteArray failed");
        return retRndKeyBytes;
    }

    /* Iteration 4: Copy result with direct access */
    genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, randomKey, &isCopy));
    if (LIKELY(genKeyNative != NULL)) {
        fast_memcpy(genKeyNative, genkeyAligned, genkeylen);
        (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative, 0);
        retRndKeyBytes = randomKey;
    } else {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
    }

    /* Iteration 4: Cleanup - release wrapped key */
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                          JNI_ABORT);

    /* Iteration 4: Secure cleanup - zero sensitive data */
    secure_zero(genkeylocal, genkeylen + 64);
    free(genkeylocal);
    ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);

    return retRndKeyBytes;
}