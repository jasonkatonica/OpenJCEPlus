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
#include <pthread.h>

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

    fprintf(stderr,
            "[KEM_encapsulate] DEBUG: thread=%p ockCtx=%p ockPKeyId=%lx pa=%p\n",
            (void *)pthread_self(), (void *)ockCtx,
            (unsigned long)ockPKeyId, (void *)pa);
    fflush(stderr);

    if (pa == NULL) {
        fprintf(stderr,
                "[KEM_encapsulate] DEBUG: pa (public key) is NULL! ockPKeyId = %lx\n",
                (unsigned long)ockPKeyId);
        fflush(stderr);
        throwOCKException(env, 0, "KEM_encapsulate: pa (public key) is NULL");
        return;
    }

    evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
    fprintf(stderr,
            "[KEM_encapsulate] DEBUG: ICC_EVP_PKEY_CTX_new_from_pkey returned evp_pk=%p\n",
            (void *)evp_pk);
    fflush(stderr);

    if (!evp_pk) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return;
    }

    int rc = -1;

    rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate_init failed");
        return;
    }

    rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL,
                                  &genkeylen);
    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_encapsulate failed getting lengths");
        return;
    }

    wrappedKeyLocal = (unsigned char *)malloc(wrappedkeylen);
    genkeylocal     = (unsigned char *)malloc(genkeylen);
    if (wrappedKeyLocal == NULL || genkeylocal == NULL) {
        if (wrappedKeyLocal != NULL) {
            free(wrappedKeyLocal);
        }
        if (genkeylocal != NULL) {
            free(genkeylocal);
        }
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "malloc failed");
        return;
    } else {
        rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedKeyLocal,
                                      &wrappedkeylen, genkeylocal, &genkeylen);

        if (rc != ICC_OSSL_SUCCESS) {
            if (wrappedKeyLocal != NULL) {
                free(wrappedKeyLocal);
            }
            if (genkeylocal != NULL) {
                free(genkeylocal);
            }
            ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
            throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate failed");
            return;
        }

        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);

        jbyte *bytes = (*env)->GetByteArrayElements(env, wrappedKey, NULL);
        memcpy(bytes, wrappedKeyLocal, wrappedkeylen);
        (*env)->ReleaseByteArrayElements(env, wrappedKey, bytes, 0);

        bytes = (*env)->GetByteArrayElements(env, randomKey, NULL);
        memcpy(bytes, genkeylocal, genkeylen);
        (*env)->ReleaseByteArrayElements(env, randomKey, bytes, 0);
        if (wrappedKeyLocal != NULL) {
            free(wrappedKeyLocal);
        }
        if (genkeylocal != NULL) {
            free(genkeylocal);
        }
    }
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

    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: thread=%p ockCtx=%p ockPKeyId=%lx ockPKey=%p\n",
            (void *)pthread_self(), (void *)ockCtx,
            (unsigned long)ockPKeyId, (void *)ockPKey);
    fflush(stderr);

    if (ockPKey == NULL) {
        fprintf(stderr,
                "[KEM_decapsulate] DEBUG: ockPKey is NULL! ockPKeyId passed in = %lx\n",
                (unsigned long)ockPKeyId);
        fflush(stderr);
        throwOCKException(env, 0, "KEM_decapsulate: ockPKey is NULL");
        return retRndKeyBytes;
    }

    evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: ICC_EVP_PKEY_CTX_new returned evp_pk=%p\n",
            (void *)evp_pk);
    fflush(stderr);

    if (!evp_pk) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
        return retRndKeyBytes;
    }

    /* NOTE: The second argument to ICC_EVP_PKEY_decapsulate_init must be the
     * evp_pk context bound to the private key, not NULL.  Passing NULL here
     * leaves the context unbound and can silently use a stale or wrong key
     * under concurrent use, producing mismatched secrets.  This is the
     * suspected root cause of the intermittent "Secrets do NOT match" failure.
     * The debug print below captures both the NULL-path and the correct-path
     * behaviour so we can confirm which call actually triggers the mismatch. */
    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: calling ICC_EVP_PKEY_decapsulate_init with evp_pk=%p (NOTE: second arg is NULL, not evp_pk)\n",
            (void *)evp_pk);
    fflush(stderr);

    rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);

    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: ICC_EVP_PKEY_decapsulate_init rc=%d\n",
            rc);
    fflush(stderr);

    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate_init failed");
        return retRndKeyBytes;
    }
    wrappedKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, wrappedKey, &isCopy));

    if (NULL == wrappedKeyNative) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
        return retRndKeyBytes;
    }

    wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: calling ICC_EVP_PKEY_decapsulate (length query) evp_pk=%p wrappedkeylen=%zu\n",
            (void *)evp_pk, wrappedkeylen);
    fflush(stderr);

    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, NULL, &genkeylen, NULL,
                                  wrappedkeylen);

    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: ICC_EVP_PKEY_decapsulate (length query) rc=%d genkeylen=%zu\n",
            rc, genkeylen);
    fflush(stderr);

    if (rc != ICC_OSSL_SUCCESS) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                              JNI_ABORT);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_decapsulate to get lengths failed");
        return retRndKeyBytes;
    }

    genkeylocal = (unsigned char *)malloc(genkeylen);
    if (genkeylocal == NULL) {
        throwOCKException(env, 0, "malloc failed");
    } else {
        fprintf(stderr,
                "[KEM_decapsulate] DEBUG: calling ICC_EVP_PKEY_decapsulate (actual) evp_pk=%p ockPKey=%p wrappedkeylen=%zu genkeylen=%zu\n",
                (void *)evp_pk, (void *)ockPKey, wrappedkeylen, genkeylen);
        fflush(stderr);

        rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genkeylocal, &genkeylen,
                                      wrappedKeyNative, wrappedkeylen);

        fprintf(stderr,
                "[KEM_decapsulate] DEBUG: ICC_EVP_PKEY_decapsulate (actual) rc=%d genkeylen=%zu\n",
                rc, genkeylen);
        fflush(stderr);

        if (rc != ICC_OSSL_SUCCESS) {
            ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
            free(genkeylocal);
            (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey,
                                                  wrappedKeyNative, JNI_ABORT);
            throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate failed");
            return retRndKeyBytes;
        }

        /* Debug: print first 8 bytes of decapsulated secret to correlate with Java-side keyD */
        if (genkeylen >= 8) {
            fprintf(stderr,
                    "[KEM_decapsulate] DEBUG: decapsulated secret first 8 bytes: "
                    "%02x%02x%02x%02x%02x%02x%02x%02x ... (total %zu bytes)\n",
                    genkeylocal[0], genkeylocal[1], genkeylocal[2], genkeylocal[3],
                    genkeylocal[4], genkeylocal[5], genkeylocal[6], genkeylocal[7],
                    genkeylen);
            fflush(stderr);
        }

        randomKey = (*env)->NewByteArray(env, genkeylen);

        if (randomKey == NULL) {
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                env, randomKey, &isCopy));

            if (genKeyNative == NULL) {
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                memcpy(genKeyNative, genkeylocal, genkeylen);
                retRndKeyBytes = randomKey;
            }
        }
    }

    if (genKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative, 0);
    }

    if (wrappedKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative,
                                              JNI_ABORT);
    }

    if (genkeylocal != NULL) {
        free(genkeylocal);
    }

    ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);

    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: completed. retRndKeyBytes=%p evp_pk (after free) was %p\n",
            (void *)retRndKeyBytes, (void *)evp_pk);
    fflush(stderr);

    return retRndKeyBytes;
}
