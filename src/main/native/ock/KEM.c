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

/* Iteration 7: Aggressive compiler optimization hints */
#ifdef __GNUC__
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define INLINE      __attribute__((always_inline)) inline
#define NOINLINE    __attribute__((noinline))
#define PREFETCH_READ(addr)  __builtin_prefetch((addr), 0, 3)
#define PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
#define ASSUME_ALIGNED(ptr, align) __builtin_assume_aligned((ptr), (align))
#define HOT         __attribute__((hot))
#define COLD        __attribute__((cold))
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#define INLINE      inline
#define NOINLINE
#define PREFETCH_READ(addr)
#define PREFETCH_WRITE(addr)
#define ASSUME_ALIGNED(ptr, align) (ptr)
#define HOT
#define COLD
#endif

/* Iteration 7: Cache line size for alignment optimization */
#define CACHE_LINE_SIZE 64

/* Iteration 7: Optimized memory operations with prefetching */
static INLINE void fast_memcpy(void *dest, const void *src, size_t n) {
    /* For small copies, use direct loop - compiler will optimize */
    if (n <= 32) {
        unsigned char *d = (unsigned char *)dest;
        const unsigned char *s = (const unsigned char *)src;
        while (n--) {
            *d++ = *s++;
        }
    } else {
        /* For larger copies, prefetch and use memcpy */
        PREFETCH_READ(src);
        PREFETCH_WRITE(dest);
        memcpy(dest, src, n);
    }
}

/* Iteration 7: Fast zero with prefetching for security-sensitive buffers */
static INLINE void secure_zero(void *ptr, size_t n) {
    PREFETCH_WRITE(ptr);
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
JNIEXPORT void JNICALL HOT
Java_com_ibm_crypto_plus_provider_ock_NativeOCKImplementation_KEM_1encapsulate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray wrappedKey, jbyteArray randomKey) {
    
    ICC_CTX          *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY_CTX *evp_pk          = NULL;
    ICC_EVP_PKEY     *pa              = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    size_t            wrappedkeylen   = 0;
    size_t            genkeylen       = 0;
    jbyte            *wrappedKeyBytes = NULL;
    jbyte            *randomKeyBytes  = NULL;
    int               rc              = ICC_OSSL_SUCCESS;

    /* Iteration 7: Prefetch key data for better cache utilization */
    PREFETCH_READ(pa);

    /* Iteration 7: Create context - optimized hot path */
    evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
    if (UNLIKELY(!evp_pk)) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return;
    }

    /* Iteration 7: Initialize encapsulation - fast path with prefetch */
    rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate_init failed");
        return;
    }

    /* Iteration 7: Get required buffer sizes - optimized with prefetch */
    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL,
                                  &genkeylen);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_encapsulate failed getting lengths");
        return;
    }

    /* Iteration 7: Get Java arrays with direct access - critical section */
    /* Prefetch array metadata for faster access */
    PREFETCH_READ(wrappedKey);
    PREFETCH_READ(randomKey);
    
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

    /* Iteration 7: Prefetch write destinations for better cache performance */
    PREFETCH_WRITE(wrappedKeyBytes);
    PREFETCH_WRITE(randomKeyBytes);

    /* Iteration 7: HOT PATH - Perform encapsulation directly into Java arrays */
    /* This eliminates malloc, alignment overhead, and memcpy operations */
    /* Assume aligned pointers for better code generation */
    unsigned char *wrappedAligned = (unsigned char *)ASSUME_ALIGNED(wrappedKeyBytes, 8);
    unsigned char *randomAligned = (unsigned char *)ASSUME_ALIGNED(randomKeyBytes, 8);
    
    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedAligned,
                                  &wrappedkeylen, randomAligned, &genkeylen);

    /* Iteration 7: Release arrays - optimized path */
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, randomKeyBytes, 
                                          LIKELY(rc == ICC_OSSL_SUCCESS) ? 0 : JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyBytes,
                                          LIKELY(rc == ICC_OSSL_SUCCESS) ? 0 : JNI_ABORT);

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
JNIEXPORT jbyteArray JNICALL HOT
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
    unsigned char    *genKeyNative     = NULL;

    /* Iteration 7: Prefetch key data for better cache utilization */
    PREFETCH_READ(ockPKey);

    /* Iteration 7: Create context - optimized hot path */
    evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
    if (UNLIKELY(!evp_pk)) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return retRndKeyBytes;
    }

    /* Iteration 7: Initialize decapsulation - fast path with prefetch */
    rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);
    if (UNLIKELY(rc != ICC_OSSL_SUCCESS)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate_init failed");
        return retRndKeyBytes;
    }

    /* Iteration 7: Prefetch array metadata for faster access */
    PREFETCH_READ(wrappedKey);
    
    /* Iteration 7: Get wrapped key with direct access - critical section */
    wrappedKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, wrappedKey, &isCopy));
    if (UNLIKELY(NULL == wrappedKeyNative)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
        return retRndKeyBytes;
    }

    wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

    /* Iteration 7: Prefetch wrapped key data for decapsulation */
    PREFETCH_READ(wrappedKeyNative);

    /* Iteration 7: Get required buffer size for secret - optimized */
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

    /* Iteration 7: Create result array BEFORE decapsulation */
    randomKey = (*env)->NewByteArray(env, genkeylen);
    if (UNLIKELY(randomKey == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                              wrappedKeyNative, JNI_ABORT);
        throwOCKException(env, 0, "NewByteArray failed");
        return retRndKeyBytes;
    }

    /* Iteration 7: Get direct access to result array */
    genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, randomKey, &isCopy));
    if (UNLIKELY(genKeyNative == NULL)) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                              wrappedKeyNative, JNI_ABORT);
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
        return retRndKeyBytes;
    }

    /* Iteration 7: Prefetch write destination for better cache performance */
    PREFETCH_WRITE(genKeyNative);

    /* Iteration 7: HOT PATH - Perform decapsulation directly into Java array */
    /* This eliminates malloc, alignment overhead, and memcpy operations */
    /* Assume aligned pointers for better code generation */
    unsigned char *wrappedAligned = (unsigned char *)ASSUME_ALIGNED(wrappedKeyNative, 8);
    unsigned char *genKeyAligned = (unsigned char *)ASSUME_ALIGNED(genKeyNative, 8);
    
    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genKeyAligned, &genkeylen,
                                  wrappedAligned, wrappedkeylen);

    /* Iteration 7: Release arrays - optimized path */
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative,
                                          LIKELY(rc == ICC_OSSL_SUCCESS) ? 0 : JNI_ABORT);
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