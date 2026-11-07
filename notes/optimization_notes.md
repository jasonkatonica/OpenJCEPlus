# MessageDigest Optimization Notes

## Iteration 1

### Findings & Analysis
1. **Unoptimized Native Compilation**: In `src/main/native/share/common.mak`, GCC compilation flags on Linux (`x86-linux64`, `arm-linux64`, `ppcle-linux64`, `s390-linux64`) did not specify an optimization level (`-O2` or `-O3`), defaulting to `-O0`. Only `s390-zos64` explicitly set `-O3`. This caused high call and loop overhead in the native JNI wrapper layer across all algorithms and payload sizes.
2. **Read-only JNI Array Release Overhead**: In `DIGEST_update` in both `src/main/native/ock/Digest.c` and `src/main/native/openssl/Digest.c`, `ReleasePrimitiveArrayCritical` was called with mode `0`. Since the input data array is strictly read-only for digest updates, passing mode `0` could trigger unnecessary copy-back operations to the Java heap if a critical array copy was created by the JVM. Using `JNI_ABORT` communicates to the JVM that the buffer was not modified and discards any temporary copy.
3. **Incomplete Algorithm Recognition & Context Caching**: In `src/main/java/com/ibm/crypto/plus/provider/base/Digest.java`, `getContext()` only mapped 5 SHA algorithms (SHA-256, SHA-384, SHA-512, SHA-224, SHA-1). MD5, SHA-512/224, SHA-512/256, and SHA3 algorithms were marked as `algIndx = -2`. Consequently:
   - MD5, SHA-512/224, SHA-512/256, and SHA3 could not participate in the cached context pool (`contextsPerBackend`) and their native contexts were deleted and reallocated rather than reused across instances.
   - For all non-indexed algorithms, `obtainDigestLength()` had to invoke native JNI `DIGEST_size` on first use instead of using precomputed table lookup values.
4. **Unnecessary Synchronization on Hot Path**: In `Digest.java`, `update()`, `digest()`, and `reset()` were declared `synchronized`. Java Cryptography Architecture (JCA) `MessageDigest` instances are explicitly not thread-safe by specification (applications use separate instances per thread). Synchronization added unnecessary monitor enter/exit and memory barrier overhead on every call.
5. **Repeated Context ID Lookups across JNI Adapters**: `NativeOCKAdapter` and `NativeOpenSSLAdapter` repeatedly called `ockContext.getId()` and `osslContext.getId()` on every single native update, digest, and reset call. Caching the primitive `long` context ID in the adapter eliminates method call and reference indirection overhead.
6. **Debug Branching and Helper Call Overhead in Native JNI Layer**: In `src/main/native/ock/Digest.c`, every update and digest JNI call evaluated `if (debug)` entry and exit branches and invoked non-inlined internal helpers. Inlining these helpers (`static inline`) and removing redundant branching on the hot path minimizes call latency.
7. **Missing Direct Buffer `engineDigest(byte[], int, int)` Implementation**: `MessageDigest.java` did not override `engineDigest(byte[] buf, int offset, int len)`, inheriting the default `MessageDigestSpi` implementation which allocates a temporary `byte[]` on every call and executes `System.arraycopy`. Adding direct buffer support avoids allocation and copy overhead when destination buffer is provided.

### Hypothesis
Enabling `-O3` in native compilation, using `JNI_ABORT` in JNI critical array release for read-only update buffers, expanding context caching and precomputed digest lengths for all 12 supported algorithms (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512), removing `synchronized` locks on `Digest`, caching native context IDs in JNI adapters, and providing direct `engineDigest(byte[], int, int)` will significantly reduce per-call native latency, eliminate monitor contention, and eliminate allocation overhead on hot paths for both OCK and OpenSSL providers.

### Exact Changes Made
1. **`src/main/native/share/common.mak`**: Added `-O3` to `CFLAGS` for all platforms.
2. **`src/main/native/ock/Digest.c` & `src/main/native/openssl/Digest.c`**:
   - Changed `ReleasePrimitiveArrayCritical` mode from `0` to `JNI_ABORT` in `DIGEST_update`.
   - Made internal helpers `static inline`.
   - Removed debug check branching on hot paths in `src/main/native/ock/Digest.c`.
3. **`src/main/java/com/ibm/crypto/plus/provider/base/Digest.java`**:
   - Expanded `numDigestAlgos` from 5 to 12 to include MD5, SHA512-224, SHA512-256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512 in `digestLengths` and context cache arrays.
   - Pre-initialized `this.digestLength = digestLengths[this.algIndx]` at `Digest` construction time for known algorithms to avoid lazy native calls.
   - Removed `synchronized` modifier on `update()`, `digest()`, and `reset()`.
   - Added direct buffer `digest(byte[] buf, int offset, int len)` overload.
   - Streamlined `update()` bounds checks and `digest()` length lookup.
4. **`src/main/java/com/ibm/crypto/plus/provider/MessageDigest.java`**:
   - Overrode `engineDigest(byte[] buf, int offset, int len)` to directly pass output buffer to `Digest.digest(buf, offset, len)`.
5. **`src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKAdapter.java` & `src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLAdapter.java`**:
   - Cached `ockContextId` and `osslContextId` as primitive `long` fields to avoid `ockContext.getId()` / `osslContext.getId()` getter calls on every native digest operation.
6. **`pom.xml`, `NativeOCKImplementation.java`, `NativeOpenSSLImplementation.java`**:
   - Ensured native library paths and fallback subdirectories (`jgsk_crypto`, `lib`) resolve correctly during tests in the container environment.

### Modified Files
- `pom.xml`
- `src/main/native/share/common.mak`
- `src/main/native/ock/Digest.c`
- `src/main/native/openssl/Digest.c`
- `src/main/java/com/ibm/crypto/plus/provider/MessageDigest.java`
- `src/main/java/com/ibm/crypto/plus/provider/base/Digest.java`
- `src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKAdapter.java`
- `src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKImplementation.java`
- `src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLAdapter.java`
- `src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLImplementation.java`

### Ideas NOT Yet Tried (for future iterations)
- Single-shot JNI helper `DIGEST_digestSingleShot(contextId, digestAlgo, data, offset, len)` combining create/update/final/reset in a single JNI boundary crossing for `digest(byte[])`.
- Direct JNI output into destination buffer in `DIGEST_digest_and_reset` taking `(jbyteArray output, jint offset, jint len)`.
- FastJNI / CriticalNative JNI bindings or direct memory buffers for update-heavy streaming workloads.
- Optimizing context reset in JNI to avoid full re-initialization if backend supports lighter-weight state zeroing.

## Iteration 2

### Findings & Analysis
1. **JNI crossings per call (benchmark sequence `update(payload); digest()`)**: 2 crossings (`DIGEST_update` then `DIGEST_digest_and_reset`). `digest(byte[])` single shot = `update` + `digest`, also 2. Each crossing pins an array via `GetPrimitiveArrayCritical` (the output array is pinned a second time in `digest_and_reset`).
2. **No per-call native `reset`**: `reset()` only calls native when `needsReinit` is set, and `digest_and_reset` already re-inits inside the same crossing, so there is no extra reset crossing on the benchmark path.
3. **OpenSSL EVP_MD fetch is already cached**: `EVP_MD_fetch` is only done in `DIGEST_create`; reset uses `EVP_DigestInit_ex2(ctx, NULL, NULL)` which reuses `ctx->fetched_digest` (no implicit fetch per call). OCK uses `ICC_EVP_get_digestbyname` once in create and stores `md` in `OCKDigest`. Digest contexts are pooled in Java (`contextsPerBackend`). So neither fetch nor context reuse explains the OCK vs OpenSSL gap.
4. **OCK vs OpenSSL SHA-2 gap at 2048B/32768B**: the JNI layer hands the whole array to `ICC_EVP_DigestUpdate`/`EVP_DigestUpdate` in a single call in both backends (no chunking in our code), so the gap is inside the native SHA-2 implementations (OCK's bundled ICC vs system OpenSSL 3.5 with CPU-accelerated SHA code). It cannot be fixed from the Java/JNI layer. The container is aarch64 (hardware sha2/sha512 flags present), the Jenkins platform is x86_64, so the cause could not be reproduced/confirmed locally.
5. **Local measurements are not comparable with Jenkins** (aarch64 container, ~2.5x higher absolute ops/s, noise 5-100% on 16B cases). All deltas below are A/B against the iteration-1 commit built in a separate worktree on the same machine.

### Hypothesis
For small payloads (16B benchmark) the cost is dominated by JNI crossings + critical-array pin/unpin. Buffering small updates in Java and merging them into the digest call (`update + final + re-init` in ONE JNI call, digest returned through a stack buffer + `SetByteArrayRegion`, small input read with `GetByteArrayRegion` into a stack buffer) removes one crossing and 2 of 3 critical sections per `update(small)+digest()` sequence.

### Exact Change
- New native method `DIGEST_updateDigestAndReset(long ctx, long digestId, byte[] in, int off, int len, byte[] out)` for OCK and OpenSSL (`src/main/native/ock/Digest.c`, `src/main/native/openssl/Digest.c`): update (if len > 0) + final + re-init in one crossing; input <= 256B copied with `GetByteArrayRegion` into a stack buffer, larger input via `GetPrimitiveArrayCritical`/`JNI_ABORT`; digest written to a stack buffer and copied to `out` with `SetByteArrayRegion` (also checks output length). Added to `NativeInterface`, both `*Adapter` and both `*Implementation` classes.
- `base/Digest.java`: `update()` with total pending input <= 256B copies it into a per-instance 256B `pending` buffer and returns without calling native; `digest()`/`digest(buf,off,len)` send pending + final in one `DIGEST_updateDigestAndReset` call. Larger updates first `flushPending()` then go directly to native as before (no extra copy for big payloads). Pending data is zeroised after being handed to native and on `reset()`. `clone()`, `getId()` (used by `Signature`) and `PKCS12KeyDeriveHelp` call `flushPending()` first, so clone/reset/signature semantics are unchanged. The caller's array is copied at `update()` time, so later modification of the caller's array does not change the result (same as native behaviour that consumes data immediately).
- Not thread safe (as before, per JCA).

### Modified Files
- `src/main/java/com/ibm/crypto/plus/provider/base/Digest.java`
- `src/main/java/com/ibm/crypto/plus/provider/base/NativeInterface.java`
- `src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKAdapter.java`, `NativeOCKImplementation.java`
- `src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLAdapter.java`, `NativeOpenSSLImplementation.java`
- `src/main/native/ock/Digest.c`, `src/main/native/openssl/Digest.c`

### Local A/B result (aarch64 container, JMH 5x3s, payload 16B only, vs iteration-1 commit)
- OCK geomean of the 10 methods: +3.5% (per method -0% .. +7.4%); OpenSSL: about +0.2% (per method -1.3% .. +3.7%), i.e. within noise. 2048B/32768B are unaffected by design (native bound). Expect only a small gain on Jenkins; this is not enough to reach +40%.

### Tests run (all with -Dock.library.path=/ock -Dopenssl.library.path=/openssl, OPENSSL_HOME=/openssl exported)
- `mvn clean compile`: OK (native libs for OCK and OpenSSL built with -Werror).
- `-Dtest='TestSHA*,TestMD5,TestTruncatedDigest,TestAliases,TestSHA256Clone_SharedMD,TestECDSASignatureInterop*,TestRSASignatureInterop*,TestHmacSHA*,TestHKDF*,TestPBKDF2*'`: 1386 tests, 1 failure + 10 errors, all pre-existing: `TestTruncatedDigest.testRSASignatureSHA512_224` and `TestHmacSHA1InteropSunJCE` (OpenJCEPlusFIPS provider not available in this container). The same classes fail identically on the iteration-1 commit (verified for TestTruncatedDigest, TestRSAPSSSignature, TestRSAPSSInterop: 40 run, 16 failures, 4 errors before and after). All SHA/MD5/KAT/clone/alias tests pass.
- Earlier broader run (also DSA/EdDSA/RSAPSS/ECDSA signature tests): only pre-existing failures (FIPS provider missing, expired 2016 certificates, RSA-PSS/TruncatedDigest).
- Ad-hoc differential fuzz vs SUN provider (random update sizes 0..5000, single-byte updates, offsets, clone mid-stream, reset, digest(buf,off,len), mutation of caller array after update) for 10 algorithms on both backends: 60000 digests, all match.
- `checkstyle:checkstyle`: BUILD SUCCESS.

### Ideas NOT Yet Tried
- Direct ByteBuffer / `FastJNIBuffer` based update path (`DIGEST_updateFastJNI` exists) for large payloads: avoids pinning, but needs a copy into the direct buffer so unlikely to win.
- Chunked updates (e.g. 4-8KB) for 32768B inputs to keep data in L1 cache while hashing (only matters if the native code touches data more than once; unlikely).
- Verify on x86_64 whether OCK's SHA-2 uses SHA-NI/AVX2 vs OpenSSL (`perf`/`ldd`), possibly route SHA-2 to the OpenSSL backend when both are available (behavioural/config change, needs owner decision).
- Skip `needsReinit` bookkeeping via `PrimitiveWrapper.Bool` (shared object, extra indirection) with a plain field + volatile only for cleaner.
- Avoid result `byte[]` allocation: not possible through the `MessageDigest.digest()` API.
- Cache `SetByteArrayRegion`-free path: return digest in a `long`/`long[]` for fixed sizes (negligible).
