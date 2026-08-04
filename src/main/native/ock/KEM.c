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

    /* GAP #1 fix: dump pub key bytes from pa so we can confirm the right key
     * is being encapsulated against (pointer alone is not enough).
     * Also print the raw key bytes starting at offset 5 (skip BIT STRING
     * header 03 82 xx xx 00) so it can be compared against the ek in dk. */
    {
        int i;
        unsigned char *epk_bytes = NULL;
        unsigned char *epk_ptr   = NULL;
        int            epk_len   = ICC_i2d_PublicKey(ockCtx, pa, NULL);
        if (epk_len > 0) {
            epk_bytes = (unsigned char *)malloc(epk_len);
            epk_ptr   = epk_bytes;
            ICC_i2d_PublicKey(ockCtx, pa, &epk_ptr);
            fprintf(stderr,
                    "[KEM_encapsulate] DEBUG: pa=%p pub key len=%d first16=",
                    (void *)pa, epk_len);
            for (i = 0; i < epk_len && i < 16; i++) {
                fprintf(stderr, "%02x", epk_bytes[i]);
            }
            fprintf(stderr, "\n");
            /* Print raw key starting at offset 5 (03 82 xx xx 00 <raw>): */
            if (epk_len >= 5 + 16) {
                fprintf(stderr,
                        "[KEM_encapsulate] DEBUG: pa=%p raw_ek (offset 5) first16=",
                        (void *)pa);
                for (i = 5; i < epk_len && i < 5 + 16; i++) {
                    fprintf(stderr, "%02x", epk_bytes[i]);
                }
                fprintf(stderr, "\n");
            }
            free(epk_bytes);
        } else {
            fprintf(stderr,
                    "[KEM_encapsulate] DEBUG: ICC_i2d_PublicKey returned %d"
                    " (no pub key in pa?)\n", epk_len);
        }
        fflush(stderr);
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

    /* Second argument to ICC_EVP_PKEY_encapsulate_init is the EVP_PKEY_CTX
     * that must be initialised for encapsulation.  Passing NULL here leaves
     * evp_pk uninitialised, so the subsequent ICC_EVP_PKEY_encapsulate call
     * operates on an uninitialised context and produces wrong/mismatched
     * ciphertext + shared secret — the root cause of the intermittent
     * "Secrets do NOT match" failure. */
    fprintf(stderr,
            "[KEM_encapsulate] DEBUG: calling ICC_EVP_PKEY_encapsulate_init with evp_pk=%p\n",
            (void *)evp_pk);
    fflush(stderr);
    rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, evp_pk, NULL);
    fprintf(stderr,
            "[KEM_encapsulate] DEBUG: ICC_EVP_PKEY_encapsulate_init rc=%d\n", rc);
    fflush(stderr);
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

        /* GAP #3 fix: dump ciphertext first16 before the JNI copy so we can
         * correlate with the test-side encapsulation print */
        {
            int i;
            fprintf(stderr,
                    "[KEM_encapsulate] DEBUG: pa=%p ciphertext len=%zu first16=",
                    (void *)pa, wrappedkeylen);
            for (i = 0; i < (int)wrappedkeylen && i < 16; i++) {
                fprintf(stderr, "%02x", wrappedKeyLocal[i]);
            }
            fprintf(stderr, "\n");
            fflush(stderr);
        }

        /* GAP #4 fix: print 16 bytes (not 8) to match Java hex16 convention */
        {
            int i;
            fprintf(stderr,
                    "[KEM_encapsulate] DEBUG: pa=%p shared secret len=%zu first16=",
                    (void *)pa, genkeylen);
            for (i = 0; i < (int)genkeylen && i < 16; i++) {
                fprintf(stderr, "%02x", genkeylocal[i]);
            }
            fprintf(stderr, "\n");
            fflush(stderr);
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

    /* ---- DEBUG: dump pub + priv key bytes accessible from ockPKey ---- */
    {
        int i;

        /* Public key */
        unsigned char *pub_bytes  = NULL;
        unsigned char *pub_ptr    = NULL;
        int            pub_len    = ICC_i2d_PublicKey(ockCtx, ockPKey, NULL);
        if (pub_len > 0) {
            pub_bytes = (unsigned char *)malloc(pub_len);
            pub_ptr   = pub_bytes;
            ICC_i2d_PublicKey(ockCtx, ockPKey, &pub_ptr);
            fprintf(stderr,
                    "[KEM_decapsulate] DEBUG: ockPKey=%p pub key len=%d first16=",
                    (void *)ockPKey, pub_len);
            for (i = 0; i < pub_len && i < 16; i++) {
                fprintf(stderr, "%02x", pub_bytes[i]);
            }
            fprintf(stderr, "\n");
            free(pub_bytes);
        } else {
            fprintf(stderr,
                    "[KEM_decapsulate] DEBUG: ICC_i2d_PublicKey returned %d"
                    " (no pub key in ockPKey?)\n", pub_len);
        }

        /* Private key — print first 16 bytes to confirm identity, plus
         * print the ek portion (encapsulation key embedded in dk) so we
         * can confirm it matches the public key bytes BC used for encap.
         *
         * ML-KEM expanded dk layout (per FIPS 203):
         *   dk = z (32) || sk (768/1152/1536) || ek (800/1184/1568) || H(ek) (32)
         * ICC stores dk inside a DER OctetString: 04 82 xx xx <dk bytes>
         * So raw dk starts at offset 4 in the DER blob returned by i2d_PrivateKey.
         *
         * ML-KEM-512 : z=32 sk=768  => ek starts at raw offset 800  => DER offset 804
         * ML-KEM-768 : z=32 sk=1152 => ek starts at raw offset 1184 => DER offset 1188
         * ML-KEM-1024: z=32 sk=1536 => ek starts at raw offset 1568 => DER offset 1572
         */
        unsigned char *priv_bytes = NULL;
        unsigned char *priv_ptr   = NULL;
        int            priv_len   = ICC_i2d_PrivateKey(ockCtx, ockPKey, NULL);
        if (priv_len > 0) {
            priv_bytes = (unsigned char *)malloc(priv_len);
            priv_ptr   = priv_bytes;
            ICC_i2d_PrivateKey(ockCtx, ockPKey, &priv_ptr);
            fprintf(stderr,
                    "[KEM_decapsulate] DEBUG: ockPKey=%p priv key len=%d first16=",
                    (void *)ockPKey, priv_len);
            for (i = 0; i < priv_len && i < 16; i++) {
                fprintf(stderr, "%02x", priv_bytes[i]);
            }
            fprintf(stderr, "\n");

            /* Print ek portion from inside dk for each variant.
             * raw dk starts at DER offset 4 (skip 04 82 xx xx header). */
            int dk_raw_len = priv_len - 4; /* approximate; exact header may vary */
            if (priv_len >= 4) {
                int ek_offset_in_der = -1;
                int ek_len           = -1;
                /* Detect variant by total priv_len:
                 *   512 : priv_len = 4 + 1632 = 1636
                 *   768 : priv_len = 4 + 2400 = 2404
                 *  1024 : priv_len = 4 + 3168 = 3172 */
                if (dk_raw_len == 1632) {
                    ek_offset_in_der = 4 + 800;  /* z(32)+sk(768)=800, +4 header */
                    ek_len = 800;
                } else if (dk_raw_len == 2400) {
                    ek_offset_in_der = 4 + 1184; /* z(32)+sk(1152)=1184, +4 header */
                    ek_len = 1184;
                } else if (dk_raw_len == 3168) {
                    ek_offset_in_der = 4 + 1568; /* z(32)+sk(1536)=1568, +4 header */
                    ek_len = 1568;
                }
                if (ek_offset_in_der >= 0 && priv_len >= ek_offset_in_der + 16) {
                    fprintf(stderr,
                            "[KEM_decapsulate] DEBUG: ockPKey=%p ek (in dk) offset=%d len=%d first16=",
                            (void *)ockPKey, ek_offset_in_der, ek_len);
                    for (i = 0; i < 16; i++) {
                        fprintf(stderr, "%02x", priv_bytes[ek_offset_in_der + i]);
                    }
                    fprintf(stderr, "\n");
                }
            }
            free(priv_bytes);
        } else {
            fprintf(stderr,
                    "[KEM_decapsulate] DEBUG: ICC_i2d_PrivateKey returned %d"
                    " (no priv key in ockPKey?)\n", priv_len);
        }

        fflush(stderr);
    }
    /* ------------------------------------------------------------------ */

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

    /* Second argument to ICC_EVP_PKEY_decapsulate_init is the EVP_PKEY_CTX
     * that must be initialised for decapsulation.  Passing NULL here leaves
     * evp_pk uninitialised, causing ICC_EVP_PKEY_decapsulate to produce the
     * wrong shared secret — the root cause of the intermittent
     * "Secrets do NOT match" failure with BouncyCastle interop. */
    fprintf(stderr,
            "[KEM_decapsulate] DEBUG: calling ICC_EVP_PKEY_decapsulate_init with evp_pk=%p\n",
            (void *)evp_pk);
    fflush(stderr);

    rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, evp_pk, NULL);

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

    /* DEBUG: print first 16 bytes of ciphertext (encapsulation) for correlation */
    {
        int i;
        fprintf(stderr,
                "[KEM_decapsulate] DEBUG: ockPKey=%p ciphertext len=%zu first16=",
                (void *)ockPKey, wrappedkeylen);
        for (i = 0; i < (int)wrappedkeylen && i < 16; i++) {
            fprintf(stderr, "%02x", wrappedKeyNative[i]);
        }
        fprintf(stderr, "\n");
        fflush(stderr);
    }

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

        /* GAP #4 fix (decap side): print 16 bytes to match Java hex16 convention */
        {
            int i;
            fprintf(stderr,
                    "[KEM_decapsulate] DEBUG: ockPKey=%p secret len=%zu first16=",
                    (void *)ockPKey, genkeylen);
            for (i = 0; i < (int)genkeylen && i < 16; i++) {
                fprintf(stderr, "%02x", genkeylocal[i]);
            }
            fprintf(stderr, "\n");
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
