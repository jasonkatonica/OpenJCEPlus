/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_create
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1create(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring digestAlgo) {

    EVP_MD      *md              = NULL;
    EVP_MD_CTX  *mdCtx           = NULL;
    const char  *digestAlgoChars = NULL;
    jlong       digestId         = 0;
    int         rc               = 1;

    if (NULL == digestAlgo) {
        throwOSSLException(env, 0, "DIGEST_create: The specified digest algorithm is null");
        return 0;
    }

    if (!(digestAlgoChars = (const char *)(*env)->GetStringUTFChars(env, digestAlgo, NULL))) {
        throwOSSLException(env, 0, "DIGEST_create: GetStringUTFChars() failed");
        return 0;
    }

    md = EVP_MD_fetch(NULL, digestAlgoChars, NULL);
    if (NULL == md) {
        throwOSSLException(env, 0, "DIGEST_create: EVP_MD_fetch failed");
        goto cleanup;
    }

    mdCtx = EVP_MD_CTX_new();
    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_create: EVP_MD_CTX_new failed");
        goto cleanup;
    }

    rc = EVP_DigestInit_ex2(mdCtx, md, NULL);
    if (1 != rc) {
        throwOSSLException(env, 0, "DIGEST_create: EVP_DigestInit_ex2 failed");
        goto cleanup;
    }

    // Everything succeeded. Set digestId to created EVP_MD_CTX.
    digestId = (jlong)((intptr_t)mdCtx);

cleanup:
    /*
     * EVP_DigestInit_ex2 calls EVP_MD_up_ref and stores the EVP_MD as
     * ctx->fetched_digest inside mdCtx.  EVP_MD_CTX_free will release that
     * reference.  We must always release our own fetch reference here,
     * regardless of success or failure, to avoid a refcount leak.
     * On the error path mdCtx is freed below (which drops its reference),
     * then we drop ours.  If mdCtx was never initialised we just drop ours.
     */
    EVP_MD_free(md);
    md = NULL;

    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);
    if (0 == digestId) {
        if (NULL != mdCtx) {
            EVP_MD_CTX_free(mdCtx);
            mdCtx = NULL;
        }
    }

    return digestId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_copy
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1copy(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {

    EVP_MD_CTX *mdCtx       = (EVP_MD_CTX *)((intptr_t)digestId);
    EVP_MD_CTX *mdCtxCopy   = NULL;
    jlong      digestCopyId = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_copy: The specified mdCtx is null");
        return 0;
    }

    mdCtxCopy = EVP_MD_CTX_new();
    if (NULL == mdCtxCopy) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_copy: EVP_MD_CTX_new failed");
        goto cleanup;
    }

    if (1 != EVP_MD_CTX_copy(mdCtxCopy, mdCtx)) {
        throwOSSLException(env, 0, "DIGEST_copy: EVP_MD_CTX_copy failed");
        goto cleanup;
    }

    // Everything succeeded. Set digestCopyId to copied EVP_MD_CTX.
    digestCopyId = (jlong)((intptr_t)mdCtxCopy);

cleanup:
    if (digestCopyId == 0) {
        if (NULL != mdCtxCopy) {
            EVP_MD_CTX_free(mdCtxCopy);
            mdCtxCopy = NULL;
        }
    }

    return digestCopyId;
}

// Optimization: Static inline helper on hot path
static inline int DIGEST_update_internal(JNIEnv *env, EVP_MD_CTX *mdCtx, unsigned char *dataNative, int dataLen) {
    int rc = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_update_internal: The specified mdCtx is null");
        return 0;
    }

    if (dataLen < 0) {
        throwOSSLException(env, 0, "DIGEST_update_internal: The specified data length is negative");
        return 0;
    }

    rc = EVP_DigestUpdate(mdCtx, dataNative, dataLen);
    if (1 != rc) {
        throwOSSLException(env, 0, "DIGEST_update_internal: EVP_DigestUpdate failed");
    }

    return rc;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_update
 * Signature: (J[BII)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1update(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray data, jint offset, jint dataLen) {

    EVP_MD_CTX     *mdCtx       = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char  *dataNative  = NULL;
    int            returnResult = 0;

    if (NULL == data) {
        throwOSSLException(env, 0, "DIGEST_update: The specified data array is null");
        return 0;
    }

    if (offset < 0) {
        throwOSSLException(env, 0, "DIGEST_update: The specified offset is negative");
        return 0;
    }

    /*
     * Optimization: the isCopy out-parameter was never read, so pass NULL
     * (explicitly allowed by the JNI specification). This removes a stack
     * slot and a store done by the VM on every large-payload update.
     */
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, NULL));
    if (NULL == dataNative) {
        throwOSSLException(env, 0, "DIGEST_update: GetPrimitiveArrayCritical failed");
        return 0;
    }

    returnResult = DIGEST_update_internal(env, mdCtx, dataNative + offset, dataLen);

    /* Release critical array with JNI_ABORT because data buffer is read-only */
    (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);

    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_updateFastJNI
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1updateFastJNI(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jlong dataBuffer, jint dataLen) {

    EVP_MD_CTX     *mdCtx       = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char   *dataNative = (unsigned char *)dataBuffer;

    if (dataNative == NULL) {
        throwOSSLException(env, 0, "DIGEST_updateFastJNI: The pointer to the specified data buffer is null");
        return;
    }

    DIGEST_update_internal(env, mdCtx, dataNative, (int)dataLen);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {

    EVP_MD_CTX     *mdCtx            = (EVP_MD_CTX *)((intptr_t)digestId);
    jbyteArray     digestBytes       = NULL;
    unsigned char *digestBytesNative = NULL;
    jboolean       isCopy            = 0;
    int            signedDigestLen   = 0;
    unsigned int   digestLen         = 0;
    int            rc                = 0;
    jbyteArray     retDigestBytes    = NULL;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_digest: The specified mdCtx is null");
        return 0;
    }

    signedDigestLen = EVP_MD_CTX_get_size(mdCtx);
    if (0 >= signedDigestLen) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest: EVP_MD_CTX_get_size failed");
        return 0;
    }

    digestBytes = (*env)->NewByteArray(env, signedDigestLen);
    if (NULL == digestBytes) {
        throwOSSLException(env, 0, "DIGEST_digest: NewByteArray failed");
        return 0;
    }

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, digestBytes, &isCopy));
    if (NULL == digestBytesNative) {
        throwOSSLException(env, 0, "DIGEST_digest: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    digestLen = (unsigned int)signedDigestLen;

    rc = EVP_DigestFinal_ex(mdCtx, digestBytesNative, (unsigned int *)&digestLen);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest: EVP_DigestFinal_ex failed");
        goto cleanup;
    }

    // Everything succeeded. Set retDigestBytes to the jbytearray with the result.
    retDigestBytes = digestBytes;

cleanup:
    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digestBytes, digestBytesNative, 0);
    }

    if ((digestBytes != NULL) && (retDigestBytes == NULL)) {
        (*env)->DeleteLocalRef(env, digestBytes);
    }

    return retDigestBytes;
}

// Optimization: Static inline helper on hot path
static inline int
DIGEST_digest_and_reset_internal(JNIEnv *env, jlong osslContextId, EVP_MD_CTX *mdCtx, unsigned char *digestBytesNative, unsigned int digestLen)
{
    int rc = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: The specified mdCtx is null");
        return 0;
    }

    if (NULL == digestBytesNative) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: The pointer to the specified data array is null");
        return 0;
    }

    rc = EVP_DigestFinal_ex(mdCtx, digestBytesNative, &digestLen);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: EVP_DigestFinal_ex failed");
        return rc;
    }

    /* digest reset */
    rc = EVP_DigestInit_ex2(mdCtx, NULL, NULL);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: EVP_DigestInit_ex2 failed");
    }

    return rc;
}
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest_and_reset
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest_1and_1reset__JJJI(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jlong digestBytes, jint length) {

    EVP_MD_CTX     *mdCtx             = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char  *digestBytesNative = (unsigned char *)((intptr_t)digestBytes);
    unsigned int   digestLen          = (unsigned int)length;

    DIGEST_digest_and_reset_internal(env, osslContextId, mdCtx, digestBytesNative, digestLen);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest_and_reset
 * Signature: (J[B)V
 *
 * Optimization: the digest (at most EVP_MAX_MD_SIZE bytes, 16-64 bytes for the
 * supported algorithms) is produced into a stack buffer and copied into the
 * caller's output array with a single SetByteArrayRegion call, exactly like
 * DIGEST_updateDigestAndReset. This replaces the previous
 * GetPrimitiveArrayCritical/ReleasePrimitiveArrayCritical pair on the tiny
 * output array (two JNI calls and a critical region held across
 * Final + Init) with one JNI call. Final and re-init are unchanged, so the
 * context is still fully reset after every successful digest.
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest_1and_1reset__JJ_3B(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray digestBytes) {

    EVP_MD_CTX    *mdCtx = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char  digestBuf[EVP_MAX_MD_SIZE];
    unsigned int   digestLen = 0;

    if (NULL == digestBytes) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset: The specified data array is null");
        return 0;
    }

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: The specified mdCtx is null");
        return 0;
    }

    if (1 != EVP_DigestFinal_ex(mdCtx, digestBuf, &digestLen)) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: EVP_DigestFinal_ex failed");
        return 0;
    }

    /* digest reset */
    if (1 != EVP_DigestInit_ex2(mdCtx, NULL, NULL)) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: EVP_DigestInit_ex2 failed");
        return 0;
    }

    /*
     * SetByteArrayRegion bounds-checks and throws
     * ArrayIndexOutOfBoundsException if the output array is shorter than the
     * digest; the exception is raised in the Java caller on return.
     */
    (*env)->SetByteArrayRegion(env, digestBytes, 0, (jsize)digestLen,
                               (const jbyte *)digestBuf);

    return 0;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_updateDigestAndReset
 * Signature: (JJ[BII[B)I
 *
 * Optimization: performs update + final + re-init in a single JNI crossing.
 * The digest is produced into a stack buffer and copied into the caller's
 * output array with SetByteArrayRegion, so the (potentially large) input array
 * is only pinned for the duration of the update and no second critical
 * section on the output array is needed.
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1updateDigestAndReset(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray data, jint offset, jint dataLen, jbyteArray output) {

    EVP_MD_CTX   *mdCtx = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char digestBuf[EVP_MAX_MD_SIZE];
    unsigned char inBuf[256];
    unsigned int  digestLen = 0;

    if ((NULL == mdCtx) || (NULL == output) || (offset < 0) || (dataLen < 0) ||
        ((dataLen > 0) && (NULL == data))) {
        throwOSSLException(env, 0, "DIGEST_updateDigestAndReset: The specified input parameters are incorrect");
        return -1;
    }

    if (dataLen > 0) {
        int rc;
        if (dataLen <= (jint)sizeof(inBuf)) {
            /* Small input: plain region copy is cheaper than a critical section */
            (*env)->GetByteArrayRegion(env, data, offset, dataLen, (jbyte *)inBuf);
            if ((*env)->ExceptionCheck(env)) {
                return -3;
            }
            rc = EVP_DigestUpdate(mdCtx, inBuf, (size_t)dataLen);
        } else {
            unsigned char *dataNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, NULL));
            if (NULL == dataNative) {
                throwOSSLException(env, 0, "DIGEST_updateDigestAndReset: GetPrimitiveArrayCritical failed");
                return -3;
            }
            rc = EVP_DigestUpdate(mdCtx, dataNative + offset, (size_t)dataLen);
            /* Input is read-only: discard any temporary copy */
            (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
        }
        if (1 != rc) {
            throwOSSLException(env, 0, "DIGEST_updateDigestAndReset: EVP_DigestUpdate failed");
            return -3;
        }
    }

    if (1 != EVP_DigestFinal_ex(mdCtx, digestBuf, &digestLen)) {
        throwOSSLException(env, 0, "DIGEST_updateDigestAndReset: EVP_DigestFinal_ex failed");
        return -1;
    }

    /* digest reset */
    if (1 != EVP_DigestInit_ex2(mdCtx, NULL, NULL)) {
        throwOSSLException(env, 0, "DIGEST_updateDigestAndReset: EVP_DigestInit_ex2 failed");
        return -2;
    }

    /*
     * No separate GetArrayLength() crossing: SetByteArrayRegion bounds-checks
     * itself and throws ArrayIndexOutOfBoundsException if 'output' is too short.
     *
     * No ExceptionCheck() after it either: this is the last JNI call of the
     * function, and a native method that returns with a pending exception has
     * that exception thrown in the Java caller as soon as it returns, which
     * makes the return value irrelevant in that case. Dropping the check saves
     * one JNI function-table call per operation.
     */
    (*env)->SetByteArrayRegion(env, output, 0, (jsize)digestLen,
                               (const jbyte *)digestBuf);

    return (jint)digestLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_size
 * Signature: (J)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1size(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {

    EVP_MD_CTX *mdCtx    = (EVP_MD_CTX *)((intptr_t)digestId);
    int        digestLen = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_size: The specified mdCtx is null");
        return 0;
    }

    digestLen = EVP_MD_CTX_get_size(mdCtx);
    if (0 >= digestLen) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_size: EVP_MD_CTX_get_size failed");
    }

    return digestLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1reset(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {

    EVP_MD_CTX *mdCtx    = (EVP_MD_CTX *)((intptr_t)digestId);
    int        rc        = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_reset: The specified mdCtx is null");
        return;
    }

    rc = EVP_DigestInit_ex2(mdCtx, NULL, NULL);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_reset: EVP_DigestInit_ex2 failed");
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_delete
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1delete(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {
    EVP_MD_CTX *mdCtx = (EVP_MD_CTX *)((intptr_t)digestId);

    if (NULL != mdCtx) {
        EVP_MD_CTX_free(mdCtx);
        mdCtx = NULL;
    }
}
