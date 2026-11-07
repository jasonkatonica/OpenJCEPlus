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
