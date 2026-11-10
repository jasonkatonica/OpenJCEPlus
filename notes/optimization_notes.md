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

## Iteration 3

### Findings & Analysis (byte path for update/digest of 2048B and 32768B)
Path (identical structure for both backends): `MessageDigest.engineUpdate` -> `base/Digest.update` -> (length > 256B, so no Java buffering) `NativeInterface.DIGEST_update` -> `Native{OCK,OpenSSL}Adapter` -> JNI `DIGEST_update` -> `GetPrimitiveArrayCritical` -> ONE `ICC_EVP_DigestUpdate` / `EVP_DigestUpdate` call with the whole array -> `ReleasePrimitiveArrayCritical(JNI_ABORT)`. Then `digest()` -> one `DIGEST_digest_and_reset` (final + re-init, 16-64B output). `digest(byte[])` = the same two crossings. Checked item by item:
1. **No Java-side chunking loop, no intermediate buffer, no zero-fill, no defensive copy** for inputs > 256B (`pending` is only used for <= 256B; large inputs call `flushPending()` which is a no-op when empty). The payload array is handed to native untouched.
2. **JNI array access does not copy.** Verified in the container with a small JNI probe (`GetPrimitiveArrayCritical(..., &isCopy)` on the same OpenJ9 VM): `isCopy == false` for 16B, 2048B, 32768B and 1MB arrays, i.e. the heap array is pinned, not copied; `JNI_ABORT` on release is a no-op. (No `GetByteArrayElements`/`GetByteArrayRegion` is used on the large path.)
3. **No native-side staging copy or per-call context work:** the whole input goes to the library's update in one call; per-call context handling is one `Final` + one re-`Init` (OpenSSL: `EVP_DigestInit_ex2(ctx, NULL, NULL)`, OCK: `ICC_EVP_DigestInit(ctx, mdCtx, md)`), constant cost independent of payload size. No `EVP_MD_fetch`/`get_digestbyname` per call (done once at create, contexts are pooled).
4. **Scaling is linear in bytes on both backends.** Local aarch64 micro-benchmark (`update(payload); digest()`, single thread, best of 7x1s, same JIT/JVM, current HEAD): SHA-256 2048B 1.09M ops/s vs 4096B 0.57M vs 32768B 74K ops/s; SHA-512 2048B 626K / 4096B 330K / 32768B 43.5K; MD5 2048B 286K / 4096B 146K / 32768B 18.6K. 32768B throughput is exactly 16x lower than 2048B (+-3%), so the fixed per-call cost (JNI crossings, pin, final+init) is already <5% of the 2048B time and ~0% of the 32768B time: SHA-256 at 32768B = 74.3K ops/s = 2.4 GB/s on both backends. The remaining time is the hash compression function itself.
5. **OCK vs OpenSSL on large inputs (aarch64 container):** SHA-256 and SHA-512 are the same speed (SHA-256 74.3K vs 74.3K at 32768B; SHA-512 43.5K vs 43.5K; 2048B within 1-3%). Both use the ARMv8 crypto-extension code (the ICC library `libicclib085.so` contains CRYPTOGAMS ARMv8 `sha256`/`sha512` block code and the same `sha256su0`/`sha512su0` instructions as system OpenSSL 3.5). MD5 (no hardware instruction, scalar code) is ~10-14% slower in OCK than OpenSSL here (18.6K vs 21.2K at 32768B), which matches the md5 gap seen on Jenkins. Therefore the 26-36% SHA-2 gap seen on the Jenkins x86_64 machine is NOT visible or reproducible here and is not caused by anything in the Java/JNI path (the code path is the same two crossings with the same arguments in both backends; the only difference is the callee). On x86_64 the likely cause is the ICC build selecting a different SHA-2 implementation than system OpenSSL 3.x (e.g. no SHA-NI/AVX2 path or an older CPU-capability dispatch in the bundled ICC); that is inside the native library and cannot be influenced from OpenJCEPlus (no ICC API to choose an implementation, and the capability vector is read by the library at load time).
6. **Per-call overhead is not what limits 2048B/32768B:** removing every remaining JNI crossing/alloc would give at most the fixed cost (~0.3-0.5us out of ~0.9us for SHA-256 2048B on this machine, i.e. a few %, and nothing at 32768B), and the only way to remove one more crossing for a >256B input would be an extra Java and native copy of the payload, which is more expensive than the crossing (see experiment).

### Hypothesis
Large-payload (2048B/32768B) throughput can be improved from the Java side only if (a) a JNI crossing can be removed for 2048B or (b) a copy/chunking cost can be removed. (b) does not exist (no copies, pinned arrays, one native update call). (a) could be tried by raising the Java-side `pending` buffer / native stack buffer limit from 256B to 2048B so that `update(2048B)+digest()` is a single `DIGEST_updateDigestAndReset` call.

### Experiment (measured and REVERTED)
Raised `PENDING_MAX` (Digest.java) and the native `inBuf` (ock/openssl Digest.c) from 256 to 2048 so that 2048B inputs are merged into one JNI call. Local result (aarch64, same harness as above), 2048B update+digest: OCK SHA-256 1092K -> 1004K ops/s (-8.1%), SHA-512 626K -> 599K (-4.3%), MD5 286K -> 279K (-2.5%); OpenSSL SHA-256 1106K -> 1010K (-8.7%), SHA-512 643K -> 610K (-5.1%), MD5 327K -> 318K (-2.6%). 4096B/32768B unchanged (go through the old path), 16B unchanged. The Java `arraycopy` + `Arrays.fill` zeroisation + native `GetByteArrayRegion` copy of 2KB costs more than the saved crossing + pin (confirms that pinned direct access is the cheaper design for >256B). Not kept; the source tree is identical to the iteration-2 commit.

### Exact Change
None in `src/`. Iteration 3 only adds this analysis; the code is unchanged versus iteration 2 (verified `git status` clean for `src/main` before committing the notes).

### Files modified
- `notes/optimization_notes.md` (this section)

### What limits large-payload throughput
- **OpenSSL backend:** the hash compression function of system OpenSSL itself (2.4 GB/s SHA-256, 1.4 GB/s SHA-512 on the aarch64 container; time is exactly linear in bytes). One pinned, zero-copy `EVP_DigestUpdate` call per payload, constant ~sub-microsecond overhead per call. Cannot be improved from OpenJCEPlus; native-bound.
- **OCK backend:** the hash compression function inside the bundled ICC library (`libicclib085.so`). Same Java/JNI path and cost as OpenSSL; identical SHA-2 speed to OpenSSL on aarch64; on Jenkins x86_64 it is 26-36% slower for SHA-2 (and 5-17% for md5/sha1), which is a property of the ICC implementation/CPU dispatch, not of OpenJCEPlus. Native-bound.
- Consequently 20 of the 30 scores per provider (2048B, 32768B) cannot be raised by further Java/JNI changes; the only levers left are outside this code (use a faster native SHA-2 for OCK, or route SHA-2 to the OpenSSL backend when both are configured) and the +40% headline target is not reachable by Java/JNI-side work alone: even if the 10 payload-16B scores improved by another +50% (very optimistic), the geomean would gain only (1.5)^(1/3) = +14.5%.

### Tests run (all with -Dock.library.path=/ock -Dopenssl.library.path=/openssl, OPENSSL_HOME=/openssl)
- `mvn clean compile`: OK (native libs for OCK and OpenSSL rebuilt with -O3 -Werror).
- `-Dtest='TestSHA256*,TestSHA512*,TestMD5,TestSHA1*'`: 239 run, 0 failures, 0 errors, 12 skipped (state unchanged from iteration 2, run to confirm the final tree).
- `checkstyle:checkstyle`: no violations.

### Ideas NOT Yet Tried
- Route SHA-2 (and md5/sha1) to the OpenSSL backend when both backends are available (config/behavioural decision; would bring OCK-provider SHA-2 large payloads up to OpenSSL speed on x86_64 if the ICC gap is real). Needs an owner decision.
- Measure on x86_64 (`perf stat`, `OPENSSL_ia32cap` for OpenSSL, `ldd`/disassembly of the ICC library) whether ICC SHA-2 uses SHA-NI/AVX2; if the OCK package has a newer ICC build or an environment switch enabling the fast path, document/ship it.
- Multi-buffer / parallel hashing is not applicable (single stream per MessageDigest).
- Further 16B work: SHA-512 16B (2.5-2.8M ops/s) vs MD5 (5.3M ops/s) is final+init cost of the 216B SHA-512 context inside the native library; only the allocation of the result `byte[]` and `MessageDigest` API dispatch remain on the Java side.

## Iteration 4

### Findings & Analysis (payload 16B, per-call overhead)
Local harness (aarch64 container, single thread, `update(16B); digest()`, best of 4x1s after 2 warm-up rounds, JIT-warm, same machine, `/tmp/h/B.java`, loaded through `--patch-module`): current code is about 69-75 ns per SHA-256 op and 147-170 ns per SHA-512 op. Native floor measured with a plain C loop calling `EVP_DigestUpdate(16B) + EVP_DigestFinal_ex + EVP_DigestInit_ex2(ctx,NULL,NULL)` against the same OpenSSL: MD5 115 ns, SHA-1 70 ns, SHA-256 62 ns, SHA-512 99 ns. Therefore the OpenSSL backend is already within ~7 ns (SHA-256) to ~35-50 ns (SHA-512) of the pure native cost, and the JNI + Java overhead left per op is only ~7-10 ns for SHA-256, the rest is Final+Init inside the library (Final+Init of an empty SHA-512 ctx is 95 ns, SHA-256 40 ns). Specific candidates checked:
- (a) result `byte[]`: allocation of 16-64 bytes by TLAB is a pointer bump, JIT escape analysis cannot remove it (returned to caller). `digest()` alone costs 58 ns (SHA-256) and `update(..)+reset()` costs 9.5 ns, i.e. the Java side (update buffering with arraycopy) is ~10 ns total. No removable allocation: the only `new byte[]` on the path is the API-mandated result. The extra 16-64B `memset` is not avoidable from Java.
- (b) `PrimitiveWrapper.Bool needsReinit`: it is a plain (non-volatile) field in a small heap object; there is no volatile, atomic, synchronized or lock on the hot path anymore (iteration 1 removed them). Replacing it with a plain field would need the Cleaner lambda to read the up-to-date value (it currently captures the shared object precisely for that), so the change would be a correctness risk for ~1 load/store pair per call (< 1 ns). Not changed.
- (c) JNI crossings: already ONE crossing per `update(<=256B)+digest()` (DIGEST_updateDigestAndReset); `flushPending` is a no-op check on the hot path, there is no context pool get/put per call (only at construction/cleaning). Nothing left to merge.
- (d) JNI side: no FindClass/GetFieldID/GetMethodID in the hot path. The 256B `inBuf` is NOT zeroed (uninitialised stack array), only `GetByteArrayRegion` copies `len` bytes. Remaining JNI function-table calls per op were: `GetByteArrayRegion`, `ExceptionCheck`, `GetArrayLength`, `SetByteArrayRegion`. **`GetArrayLength` was redundant**: `SetByteArrayRegion` already bounds-checks and throws `ArrayIndexOutOfBoundsException` (the Java caller always passes an array of exactly the digest length, so the check never triggers anyway).
- (e) API dispatch: `java.security.MessageDigest` (JDK) -> `engineUpdate` -> `Digest.update`; `engineDigest` -> `Digest.digest`. Bounds checks are the minimum required by the contract (needed also for the `System.arraycopy` safety), one array-length compare each; try/catch costs nothing on the non-exceptional path. No string comparisons per call (the algorithm switch is in the constructor only).

### Hypothesis
Removing the redundant `GetArrayLength` JNI crossing (one function-table call, non-inlinable in the interpreter/JNI stub) from `DIGEST_updateDigestAndReset` saves ~1-3 ns of the 60-170 ns per op; the effect is a ~0.5-1.5% gain at 16B, nothing at 2048B/32768B (<0.1%).

### Exact Change
`src/main/native/ock/Digest.c` and `src/main/native/openssl/Digest.c`, function `DIGEST_updateDigestAndReset`: removed `GetArrayLength(output) < digestLen` check; `SetByteArrayRegion` (which performs the same bounds check itself and throws `ArrayIndexOutOfBoundsException`) is followed by `ExceptionCheck` and returns an error code if it threw. The Java `Digest.digestInto` always supplies an array of exactly the digest length, so behaviour for callers is identical (digests unchanged, no new exception on the normal path).

### Files modified
- `src/main/native/ock/Digest.c`
- `src/main/native/openssl/Digest.c`
- `notes/optimization_notes.md` (this section)

### Local A/B (aarch64 container, 16B `update+digest`, geomean of MD5/SHA-1/SHA-256/SHA-512/SHA-512-224, 3 alternating runs each, ops/s)
- OCK: base 8867508 / 8878222 / 8857475 -> new 8952457 / 8969966 / 9007596 (about +1.2%; SHA-256 +1.5-1.9%, MD5 +1.7-4.4%, SHA-512 ~0%).
- OpenSSL: base 9866440 / 9793183 / 9987727 -> new 9976942 / 10015539 (about +0.7-1.0%).
- Small, within run-to-run noise on a single run but consistent in the A/B pairs. Do not expect more than ~+1% on Jenkins at 16B and nothing at 2048B/32768B.
- Other micro-experiments (not kept): native floor measurement showed `EVP_DigestInit_ex` vs `_ex2` identical (no gain from changing the re-init call); output pointer alignment irrelevant.

### Tests run (all with -Dock.library.path=/ock -Dopenssl.library.path=/openssl, OPENSSL_HOME=/openssl)
- `mvn clean compile`: BUILD SUCCESS (OCK and OpenSSL native libs rebuilt with -O3 -Werror).
- `-Dtest='TestSHA256*,TestSHA512*,TestMD5,TestSHA1*,TestSHA224*,TestSHA384*,TestSHA3*,TestSHA256Clone_SharedMD,TestAliases,TestTruncatedDigest'`: 705 run, 1 failure, 0 errors, 12 skipped. The only failure is the pre-existing `TestTruncatedDigest.testRSASignatureSHA512_224` (OpenJCEPlusFIPS provider not available in the container; documented in iteration 2, identical on earlier commits).
- `mvn checkstyle:checkstyle`: BUILD SUCCESS.

### Conclusion / what remains
After this change the Java/JNI layer is within ~10 ns of the native floor for SHA-256 and within ~30-50 ns for SHA-512 per update+digest op on this machine; everything left is the library's Final+Init (SHA-512/MD5 contexts are costlier). No further meaningful 16B win from Java/JNI work was found; the +40% target remains out of reach without changing the native hashing.

### Ideas NOT Yet Tried
- Avoid the library's `Final` + `Init` pair for fixed 16B..<=256B one-shot digests by using a one-shot `EVP_Q_digest`/`EVP_Digest` style call on a fresh stack context for tiny inputs (needs checking that it is not slower than the cached ctx; for OpenSSL 3.x `EVP_Digest` includes an implicit fetch, so likely slower unless the `EVP_MD*` is cached - would need a new native entry holding the `EVP_MD*`; and for OCK no equivalent known).
- Replace `JNI` with a Panama/`Linker` downcall (JDK 22+) for tiny calls: removes JNI transition cost, but needs native-memory segments (copy) and the JDK baseline of the project must be checked; large refactor, uncertain on OpenJ9.
- Plain-field `needsReinit` with the Cleaner reading it from the `Digest` weak/phantom-safe holder (< 1 ns, correctness risk).

## Iteration 5

### Hypothesis
The remaining 16B cost is the native library's Final+Init pair. Candidates evaluated (Ideas NOT Yet Tried from iteration 4 and the task): (1) a one-shot `EVP_Digest`/`EVP_Q_digest` call for tiny inputs with a cached `EVP_MD*`; (2) replacing the in-place re-init (`EVP_DigestInit_ex2(ctx,NULL,NULL)`) after Final with `EVP_MD_CTX_copy_ex(ctx, pristineTemplate)`; (3) OCK: a cheaper reset/one-shot path in the ICC API, or less wrapper work; (4) Java side only if profiling still shows cost. Required win to keep a change: > 2% locally at 16B without hurting 2048B/32768B.

### What was measured (aarch64 container, OpenSSL 3.5.8, ICC 8.5; `/tmp/h5/*.c`, plain C loops, 16B input, best of 5x2-3M iterations, ns/op)
| Variant (MD5 / SHA-1 / SHA-256 / SHA-512) | ns/op |
|---|---|
| current: `Update + Final_ex + Init_ex2(ctx,NULL,NULL)` | 115 / 70 / 62 / 100 |
| `Init_ex2(ctx,md)` instead of `(NULL,NULL)` | identical |
| `Final_ex` with NO re-init (lower bound of any re-init trick) | 116 / 69 / 62 / 100 |
| `Update + Final_ex + EVP_MD_CTX_copy_ex(ctx, tmpl)` | 111 / 66 / 57.5 / 100 |
| `EVP_Digest()` one-shot with cached `EVP_MD*` | 146 / 105 / 97 / 151 (+30-50%) |
| `EVP_Q_digest()` one-shot (implicit fetch) | 220-270 (2-4x slower) |
| legacy `SHA256()`/`SHA512()` one-shot | 226 / 283 (slower, provider shim) |
| `EVP_MD_CTX_new + Init + Update + Final + free` per op | 128-181 (much slower) |
| low-level `SHA256_Init/Update/Final` (deprecated API, not usable through providers/FIPS) | 44 / 81 (SHA-256 / SHA-512), MD5 97, SHA-1 50 |
| extra 16-64B memcpy of the digest (stack buf -> output) | +7-9 ns (we already copy once via `SetByteArrayRegion`; passing the Java array directly is not possible without a critical section which costs more) |

Findings:
- The in-place re-init (`Init_ex2(NULL,NULL)`) costs only ~0.5-1 ns on top of Final: Init is NOT the cost. Final itself (padding + one compression + provider dispatch) is ~85% of the 16B native time. Therefore the "avoid Final+Init pair" idea has no big upside: any scheme still needs one Final, and the Init part is already ~free. SHA-512 shows no gain at all from any variant.
- One-shot `EVP_Digest()` (even with a cached `EVP_MD*`) is 30-50% SLOWER than the cached-context path because it allocates and frees a context per call; `EVP_Q_digest` is 2-4x slower because of the implicit fetch. Rejected.
- `EVP_MD_CTX_copy_ex(ctx, template)` is the only variant that helped natively (3-5 ns for MD5/SHA-1/SHA-256, 0 for SHA-512): it skips the provider init path (dup of the small algorithm state instead). Prototype (extra per-digest `OSSLDigest {ctx, tmpl}` struct as `digestId`, template created in DIGEST_create/DIGEST_copy, freed in DIGEST_delete, reset via copy_ex in `DIGEST_updateDigestAndReset`/`digest_and_reset`/`DIGEST_reset`) was built into the real `libopenjceplus.so` and measured through the Java API (`update(16B); digest()`, JIT-warm, best of 3 runs, 3 alternating A/B pairs, `/tmp/h5/j/B.java`): MD5 121.5->118.8, SHA-1 75.7->76.5 (one run 73.2), SHA-256 66.6->63.9, SHA-512 125.4->125.3, SHA-512/224 124->124. Geomean of the 5 algorithms: +0.9% / -0.5% / +1.0% over the three pairs (about +0.5% average, individual runs were up to +2.6% when MD5 got lucky, and one run lost 15 ns on MD5 to noise). 2048B and 32768B unchanged (within +-1%). On Jenkins this is at most ~0.2% on the headline (16B is one third of the scores and the gain applies to 16B only). Below the 2% bar and it adds an allocation + a second native context per digest (and a more complicated clone/delete lifetime), so NOT kept; source reverted.
- OCK (ICC) side: the ICC API (`icc_a.h`, `libjgsk8iccs_64.so` exports) offers no `EVP_Digest` one-shot, no `DigestInit_ex`, no `MD_CTX_reset`, only `ICC_EVP_MD_CTX_copy`, `_cleanup`, `_init`, `DigestInit/Update/Final`. Measured natively: `Update+Final+DigestInit(ctx,md)` = 131 / 70 / 67 / 143 ns (MD5/SHA-1/SHA-256/SHA-512); `ICC_EVP_DigestInit` alone is only ~6 ns; the template approach `ICC_EVP_MD_CTX_copy(work, tmpl)` is 30-40 ns SLOWER (165 / 104 / 99 / 184 ns) because ICC's copy allocates/duplicates the inner EVP state. So there is no cheaper reset for OCK: Init is already 6 ns of 70-143 ns, and the rest is Update+Final. No wrapper change possible (the wrapper has no lock/mutex or lookup on the hot path since iteration 1/2).
- Java side: unchanged conclusion from iteration 4 (end-to-end Java API cost vs native floor on the OpenSSL backend: SHA-256 66.5 ns vs 62 ns native; SHA-512 125 ns vs 100 ns; MD5 121 vs 115; SHA-1 76 vs 70). Remaining Java+JNI overhead is 5-25 ns per op, with no removable piece found.

### Exact change
None in `src/`. The prototype was reverted (`git checkout src/main/native/openssl/Digest.c`); the tree is identical to iteration 4. Only this notes section is committed. No tests needed for notes-only change; native libs were rebuilt from the unchanged source to confirm the tree compiles (`-O3 -Werror`).

### Learnings
- At 16B the native cost is dominated by Update+Final of the library's compression function (one block); Init/reset is ~6-12 ns (<10%) in both OpenSSL and ICC. Any reset trick is bounded by that, and `EVP_MD_CTX_copy_ex(template)` realises only a third to a half of it for MD5/SHA-1/SHA-256 and nothing for SHA-512 (+0.5% end to end).
- One-shot APIs (`EVP_Digest`, `EVP_Q_digest`, legacy `SHA256()`) are slower than the pooled, long-lived `EVP_MD_CTX` already used here; keep the pooled contexts.
- The 16B per-op time of the Java API is within ~5% (SHA-256, MD5, SHA-1) to ~25% (SHA-512) of the pure native Update+Final+Init loop, so there is no remaining per-call lever at 16B that yields >2%. Together with iteration 3 (2048B/32768B are bound by the compression function, 20 of 30 scores per provider), the +40% headline target is not reachable without changing the native hash implementation (e.g. a faster ICC build for x86_64 SHA-2, or routing SHA-2 to the OpenSSL backend on x86_64) or reducing the JNI transition itself (Panama downcalls; still untested, needs native-memory copy and OpenJ9 support check).

### Ideas NOT Yet Tried
- Panama `Linker` downcalls (JDK 22+) with `Critical`-style linkage to remove the JNI transition (5-25 ns per op), only worthwhile if the project baseline allows JDK 22+ and the OpenJ9 build supports it.
- Routing SHA-2 (and MD5/SHA-1) of the OCK provider to the OpenSSL backend on x86_64 (configuration/behavioural decision for the owners).
- Measuring on real x86_64 (where the ICC SHA-2 gap is 26-36% at 2048B/32768B) whether ICC uses SHA-NI/AVX2.

## Iteration 6

NO LOCAL MEASUREMENT in this iteration (by instruction): nothing was benchmarked or timed. The decision below rests on code reading, `javap -c` bytecode sizes and call-graph analysis only. Performance is to be judged by the Jenkins x86_64 JMH job.

### Hypothesis
At payload 16B the hot path is `update(payload)` (Java-side buffering only, 0 JNI calls) + `digest()` (exactly 1 JNI call, `DIGEST_updateDigestAndReset`). Inside that one JNI native, after the last `SetByteArrayRegion` there was still an `ExceptionCheck()` JNI function-table call whose only purpose was to pick a different (irrelevant) return value when an exception is pending. Removing it strictly removes one JNI function call per 16B operation on both backends and cannot change behaviour.

### Code-analysis reasoning

1. **JIT-friendliness of the Java hot path** (`javap -c -p` on the freshly compiled classes; bytecode sizes in bytes):
   - `MessageDigest.engineUpdate(byte[],int,int)` 74, `engineDigest()` 19, `engineDigest(byte[],int,int)` 86, `engineReset()` 22.
   - `Digest.update` 187, `digest()` 48, `digest(byte[],int,int)` 82, `digestInto` 97, `flushPending` 75, `reset` 86, `getDigestLength` 15.
   - All are above HotSpot's `MaxInlineSize` (35) but well below `FreqInlineSize` (325), so on a hot call site they are inlined by size (and the OpenJ9 JIT, which is what runs here, uses its own size/budget heuristic, not these flags; every method is far below its hot-method limits). The whole chain `Delegate.engineUpdate -> MessageDigest.engineUpdate -> Digest.update` (74 + 187) and `engineDigest -> digest -> digestInto` (19 + 48 + 97) is small enough to inline into one compilation unit; no method on the path is large because of cold code (the exception-construction blocks are at the tail of each method and are not executed; `throwNativeException` is already a separate static helper; `getContext`, 827 bytes, is constructor-only).
   - Call sites: `Delegate -> spi.engineUpdate` is a virtual call on `MessageDigestSpi` (static type) so it cannot be devirtualised by CHA (other `MessageDigestSpi` subclasses exist in the JDK) and the receiver profile is polymorphic in the benchmark (6 final subclasses of the abstract `MessageDigest`, all sharing the same inherited `engineUpdate`). Making provider methods `final` cannot change that (the call site is typed `MessageDigestSpi`, in JDK code we do not control). `Digest` is a `final` class with `private`/non-overridden methods, so all calls inside the provider are already statically bound; `nativeInterface.DIGEST_*` is an interface call whose receiver is one concrete class per run (OCK or OpenSSL adapter, with `FIPS`/`NonFIPS` subclasses of which only one is loaded per provider) and `NativeXAdapter.DIGEST_* -> NativeXImplementation.DIGEST_*` is a static native call: monomorphic/bimorphic, inlinable.
   - Duplicate checks: `engineUpdate` and `Digest.update` both validate `input != null`, `offset >= 0`, `length >= 0`, `offset <= input.length - length` (4 compare/branch pairs, <1 ns). `Digest.update` is also called by `base/Signature.update`, whose own check is `offset + length > input.length` (overflow-prone), so the `Digest.update` check is the one that protects the native/arraycopy path for that caller. After inlining, the JIT's value propagation can usually fold the second check; removing it by hand would shift safety to callers and is not "strictly safe", so it is NOT changed.
   - Field re-reads (`pendingLen`, `pending`, `digestId`, `nativeInterface`) are plain fields, no volatile/lock, so the JIT can CSE them within the inlined body. `needsReinit.setValue()` is a plain-field store (already evaluated and rejected in iteration 4 because of the Cleaner).
   - No exceptions/checks on the hot path that could be moved to a cold helper with measurable benefit: `try/catch` in `MessageDigest` is table-driven (free when not thrown), `Arrays.fill` zeroisation of pending data in `finally` is intentional (security) and it is only `len` bytes.
   - Conclusion: no Java change that strictly removes work; no change made on the Java side.

2. **JNI transitions per operation (counted by reading `Digest.update/digest/digestInto` and the natives):**

   | Benchmark sequence | Backend | JNI calls | Which |
   |---|---|---|---|
   | `update(16B)` + `digest()` | OCK and OpenSSL | 1 | `DIGEST_updateDigestAndReset` (update is only an `arraycopy` into `pending`) |
   | `digest(16B)` | OCK and OpenSSL | 1 | same (`MessageDigest.digest(byte[])` = `update` + `digest()`) |
   | `update(2048B/32768B)` + `digest()` / `digest(payload)` | OCK and OpenSSL | 2 | `DIGEST_update` (pinned, zero-copy) and `DIGEST_digest_and_reset` (16-64B output) |

   For 16B the count is already the minimum of 1. For 2048B/32768B the 2 calls are structural: merging them would require either copying the payload (tested and rejected in iteration 3: slower) or retaining a reference to the caller's array until `digest()` (unsafe: the caller may modify the array between `update` and `digest`). Note for the future: the large-payload `DIGEST_digest_and_reset(byte[])` native pins the 16-64B output array with `GetPrimitiveArrayCritical`/`ReleasePrimitiveArrayCritical` (2 JNI function calls); producing into a stack buffer and `SetByteArrayRegion` (1 call) as `DIGEST_updateDigestAndReset` does would remove one function call, but it only affects 2048B/32768B whose per-op times are 5 us to 2 ms, so the saving (a few ns) is far below measurable (<0.1%) and is NOT done in this iteration.

   **JNI function-table calls inside the 16B native, before and after this iteration** (`DIGEST_updateDigestAndReset`, both backends): before: `GetByteArrayRegion`, `ExceptionCheck`, `SetByteArrayRegion`, `ExceptionCheck` (4); after: `GetByteArrayRegion`, `ExceptionCheck`, `SetByteArrayRegion` (3). The first `ExceptionCheck` stays: it is required to avoid feeding uninitialised `inBuf` to the hash if `GetByteArrayRegion` failed.

3. **Feasibility analysis only (no implementation, no timing) of JNI alternatives**
   - **What the environment offers (checked by inspection and API probing only, no timing):** the project builds with `jdk.build.target` 25 and the runtime here is IBM Semeru/OpenJ9 25 (`java.lang.foreign` is final in JDK 22+, no preview flag). `Linker.nativeLinker()`, `Linker.defaultLookup()`, `downcallHandle(...)` and `Linker.Option.critical(boolean)` exist and a trivial `strlen` downcall (plain, `critical(false)`, and `critical(true)` with a heap segment) functionally works on this OpenJ9 25 build (aarch64). The x86_64 SysV linker classes (`SysVx64Linker`) are the code path of the JDK 25 class library on Jenkins; OpenJ9 on x86_64 Linux supports FFM downcalls in JDK 22+ (this was not verified on x86_64 here).
   - **Pros:** no `JNIEnv` function-table calls (no `GetByteArrayRegion`/`SetByteArrayRegion`/`ExceptionCheck`); `Option.critical(true)` allows passing heap `MemorySegment`s (no pinning cost, no copy) for short native calls, which would be the closest equivalent to a JNI critical native; downcall handles bound as `static final MethodHandle` are inlined by the JIT as a direct native call with a thin thread-state transition; removes the hand-written JNI C wrapper from the hot path (calls `EVP_DigestUpdate/Final/Init` directly, with `Final`+`Init` still needing 2 downcalls or a small C helper).
   - **Cons:** the digest operation is `Update + Final + Init` on an opaque context pointer; with FFM that is 3 downcalls (or 1 downcall to a small C helper, which is just JNI minus the `JNIEnv`), each with its own transition, unless a C helper is kept; output must go into a `MemorySegment` (heap segment only with `critical(true)`, which is not allowed to call back into the JVM or block; OpenSSL/ICC `Final` is fine for that but any provider/FIPS callback to `malloc`-heavy or locking code is a risk of long GC-blocking critical regions); OCK/ICC is reached through our own `libjncrypto`-style wrapper with function pointers resolved by ICC context (`ICC_CTX`), so a direct FFM binding would need new symbol lookup/ABI work for ICC; the module/jar needs `--enable-native-access` (warning in JDK 24+ otherwise) which is a deployment/behaviour change for every consumer; must remain correct on z/OS, AIX, ppc64le, s390x, Windows where the project builds (FFM availability and `critical` support differ per OpenJ9 platform); `Arena`/`MemorySegment` allocation or `MemorySegment.ofArray` wrapper objects per call can be scalar-replaced by the JIT only if inlining succeeds, which is less reliable in OpenJ9's JIT than in HotSpot's C2 (OpenJ9 does not have the same escape-analysis guarantees; unverified).
   - **Risks:** performance is unproven on OpenJ9 (the OpenJ9 FFM implementation uses its own downcall thunks and may have a higher fixed cost than a JNI call with `static native`); the ~5-25 ns total Java+JNI overhead per 16B op measured earlier is the ceiling of what this could save and the 2048B/32768B scores (20 of 30 per provider) would not move; large refactor touching all native classes and Cleaner lifetime; build must still support the older JDK profiles if any other JDK profile exists in `pom.xml` (currently only the JDK 25 profile is present).
   - **OpenJ9 JNI critical natives / `@CriticalNative`:** not available as a public mechanism in OpenJ9 (HotSpot's `-XX:+CriticalJNINatives` was removed in JDK 22 and was never an OpenJ9 feature); the OpenJ9 equivalent is the JIT's internal JNI "fast path" (JNI helper inlining for `static native` methods with simple signatures), which already applies here because the natives are `static`, have primitive/array arguments only, and have no `synchronized`. Nothing to opt into from the Java source.
   - **Recommendation:** do not implement without an owner decision and a Jenkins-measured prototype restricted to one algorithm; if prototyped, use `critical(true)` + heap segments for the 16B path only and keep the JNI path as a fallback.

### Exact change
`src/main/native/ock/Digest.c` and `src/main/native/openssl/Digest.c`, function `DIGEST_updateDigestAndReset`: removed the `ExceptionCheck()` that followed the final `SetByteArrayRegion` (and its `return FAIL_DIGEST_FINAL` / `return -1`). This is the last JNI call in the function. If `SetByteArrayRegion` throws (`ArrayIndexOutOfBoundsException`, only possible if the output array is shorter than the digest, which the Java caller never does) the exception stays pending and is thrown in the Java caller the moment the native returns; the return value is not used in that case, so behaviour is identical on every path while one JNI function-table call is saved on every 16B `digest()`. Applies identically to OCK and OpenSSL; no effect on the 2048B/32768B path (they use `DIGEST_update` + `DIGEST_digest_and_reset`, untouched).

### Why it is strictly removing work and safe
- Fewer instructions on the hot path: one indirect call through the `JNINativeInterface` table (a load of the function pointer, call, return, and in OpenJ9's implementation a check of the pending-exception field) disappears per op; nothing was added.
- Safety: JNI specification: a pending exception is raised in the caller when the native method returns, whatever the return value is. The Java side (`Digest.digestInto`) only evaluates the return value when no exception was thrown; no native resource is held at that point (the digest context was already reset, the input critical region already released), so there is nothing to clean up on that path. Thread-safety and Cleaner/native lifetime logic are not touched.

### Tests run (targeted correctness only, no performance measurement; `-Dock.library.path=/ock -Dopenssl.library.path=/openssl`, `OPENSSL_HOME=/openssl`)
- `mvn test -Dtest='TestSHA256*,TestSHA512*,TestMD5,TestSHA1*,TestSHA224*,TestSHA384*,TestSHA3*,TestSHA256Clone_SharedMD,TestAliases,TestTruncatedDigest'`: native libraries rebuilt with `-O3 -Werror` (OK), 705 tests run, 1 failure, 0 errors, 12 skipped. The single failure is the known pre-existing `TestTruncatedDigest.testRSASignatureSHA512_224` (OpenJCEPlusFIPS provider unavailable in the container).
- `mvn checkstyle:checkstyle`: no violations.

### Learnings
- The Java path is already small and is entirely inlinable by size; the remaining visible non-library cost at 16B is JNI function-table calls inside the native wrapper (now 3: `GetByteArrayRegion`, `ExceptionCheck`, `SetByteArrayRegion`). The next possible removals are only possible by changing the JNI transition mechanism (Panama, analysed above) or by giving up the `GetByteArrayRegion` copy for tiny inputs (needs pinning, which costs more).
- Expect the effect of this change to be tiny (about one function-table call per 16B op, comparable to or smaller than iteration 4's GetArrayLength removal) and invisible at 2048B/32768B; Jenkins will show whether it is distinguishable from noise.
- The +40% headline target is still bounded by the native compression function for 20 of 30 scores per provider (see iterations 3 and 5).

### Ideas NOT Yet Tried
- Large-payload `DIGEST_digest_and_reset(byte[])`: stack buffer + `SetByteArrayRegion` instead of a critical section on the 16-64B output (one JNI call fewer; affects only 2048B/32768B, expected below noise).
- Prototype a Panama `critical(true)` downcall for the 16B path of one algorithm and measure on Jenkins (requires owner approval).
- Routing SHA-2 of the OCK provider to the OpenSSL backend on x86_64; ICC CPU-dispatch investigation (unchanged from iteration 5).

## Iteration 7

NO LOCAL MEASUREMENT in this iteration (by instruction): nothing was benchmarked or timed and no performance numbers are recorded. Decisions rest on code reading and cost reasoning only; Jenkins x86_64 JMH is the judge.

### Hypothesis
For 2048B/32768B payloads (20 of 30 scores per provider) each `update(payload)` + `digest()` makes 2 JNI calls: `DIGEST_update` (input pinned) and `DIGEST_digest_and_reset(byte[])`. The latter pinned the 16-64B output array with `GetPrimitiveArrayCritical` and released it with `ReleasePrimitiveArrayCritical` around `Final` + `Init`. Replacing the pair by a stack buffer + one `SetByteArrayRegion` (as `DIGEST_updateDigestAndReset` already does) strictly removes one JNI function call and one critical region per operation. The saving is a fixed few ns per op, so it is expected to be invisible at 2048B/32768B (per-op time is several microseconds or more); it is a strict reduction of work only.

### Code-analysis reasoning

1. **Is `GetPrimitiveArrayCritical` the cheapest correct pin for the large input in `DIGEST_update`? Yes, keep it.**
   - Alternatives: `GetByteArrayElements` allocates a native buffer and copies the whole array (2KB/32KB) in, and `Release...` has to free it (with `JNI_ABORT` no copy back); `GetByteArrayRegion` into a stack/heap buffer is the same copy, and for 32KB a stack buffer is not appropriate, a malloc would be needed. Both do O(n) extra memory traffic per op plus allocation; the hash itself reads each byte once. The critical variant pins the heap array (no copy, `isCopy == false` was verified on this OpenJ9 in iteration 3 for 16B, 2KB, 32KB and 1MB arrays) and `JNI_ABORT` on release is then just the unpin.
   - The price of critical access on OpenJ9 is that the thread holds VM access / blocks GC for the duration of the native update (about 5us at 2KB; tens of microseconds to ~2 ms at 32KB). That is a latency/GC-pause concern, not a throughput cost in a single-threaded JMH run, and it is already the established design (iteration 3 measured that copying 2KB into a stack buffer was 2.5-8.7% slower). No change.
   - Java side (`base/Digest.update`): for `length > 256` the path is `length == 0` check, argument validation (4 compares), `digestId` check, the `length <= PENDING_MAX - pendingLen` test, `flushPending()` (returns on `pendingLen == 0`), second `length <= PENDING_MAX` test, then one `DIGEST_update` interface call and `needsReinit.setValue(true)`. No chunking, no zero fill, no defensive copy, no second update call when nothing is pending. `MessageDigest.engineUpdate` repeats the range check (analysed and left in place in iteration 6: `Signature` also calls `Digest.update` and the check protects the native/arraycopy path). Native `DIGEST_update` does a null/offset check, the pin, one `EVP_DigestUpdate`/`ICC_EVP_DigestUpdate` call and the release; the internal helper has only null/negative-length compares. Nothing strictly removable.

2. **`DIGEST_digest_and_reset(byte[])` -> stack buffer + `SetByteArrayRegion` (IMPLEMENTED).**
   - Size bound: the digest length is bounded by `EVP_MAX_MD_SIZE` (OpenSSL, 64 bytes) and `ICC_EVP_MAX_MD_SIZE` (OCK). Both are already used for `digestBuf` in `DIGEST_updateDigestAndReset` in the same files, so the symbols and their sizing are known to build and to be adequate for every algorithm this provider supports (max 64 bytes: SHA-512, SHA3-512). Using `digestLen` returned by `Final` as the copy length is the same approach as in `DIGEST_updateDigestAndReset`.
   - Context reset on all paths is unchanged: `Final` then `Init` are executed exactly as before (OpenSSL: `EVP_DigestFinal_ex` + `EVP_DigestInit_ex2(ctx, NULL, NULL)`; OCK: `ICC_EVP_DigestFinal` + `ICC_EVP_DigestInit(ctx, md)`), before the copy-out. If `Final` fails the function returns without `Init` exactly like the old `DIGEST_digest_and_reset_internal` (same return values: OCK `FAIL_DIGEST_FINAL` / `FAIL_DIGEST_INIT` which `Digest.throwNativeException` maps; OpenSSL throws a Java exception as before and returns 0). The old code also had no reset on the `GetPrimitiveArrayCritical` failure path, so no error path lost a reset. The long-pointer overload `DIGEST_digest_and_reset(JJJI)` and the `static inline ..._internal` helpers are untouched (the OCK helper is still used by `DIGEST_PKCS12KeyDeriveHelp`).
   - Exception semantics: the null `digestBytes` / null `mdCtx` (OpenSSL) / null `ockDigest` (OCK) checks still throw the same exceptions. The only behavioural difference is on a case the Java caller never produces: `Digest.digestInto` passes an array that is exactly the digest length (or a temp array of that length). If the array were too short, the old code wrote past the end of the Java array inside the critical region (heap overflow); the new code throws `ArrayIndexOutOfBoundsException` from `SetByteArrayRegion` (pending exception raised in the caller on return, as in `DIGEST_updateDigestAndReset` since iteration 6). Strictly safer.
   - Leakage: the stack buffer holds the digest only; the digest is non-secret output, identical to what `DIGEST_updateDigestAndReset` already leaves on the stack. Full context reset between operations is unchanged. Thread-safety, Cleaner and native-resource lifetime are unchanged (no Java edits; no native resource added).
   - Cost: before = `GetPrimitiveArrayCritical` + `ReleasePrimitiveArrayCritical` (two JNI calls, a critical region held across `Final` + `Init`) ; after = one `SetByteArrayRegion` of 16-64 bytes (one JNI call, plus a 16-64B memcpy). The critical region no longer spans the library `Final`/`Init` (shorter GC-blocking window). Net work removed: one JNI function-table call and the critical-section bookkeeping (VM access / critical counter handling) per large-payload digest.

3. **Other possible removals on the large path (none found).**
   - No redundant ctx reset: `digest()` does one `Final` + one `Init` (needed so the object is reusable); `DIGEST_update` does not reset. `Digest.reset()` only calls native if `needsReinit` and is not part of the benchmark path.
   - No extra zeroing: `pending` is only used and zeroed for <= 256B inputs; `digestBuf` is not zero-initialised (uninitialised stack array).
   - No extra JNI call: exactly 2 per op (structural; merging them was rejected in iteration 3 and in iteration 6 for the reasons recorded there). `engineDigest()` -> `Digest.digest()` -> `digestInto` -> `DIGEST_digest_and_reset` when `pendingLen == 0`; `new byte[len]` is the API-mandated result. `engineDigest(byte[],int,int)` goes directly to `digestInto` when `offset == 0 && buf.length == dLen`.
   - `DIGEST_update` still does `GetPrimitiveArrayCritical` with an `&isCopy` out-parameter (a store the JVM fills in). Passing `NULL` is equally valid JNI and removes one stack store; not changed here since it is below any meaningful level and iteration 3 already confirmed pinning without copy.

### Exact change
`src/main/native/openssl/Digest.c` and `src/main/native/ock/Digest.c`, function `DIGEST_digest_and_reset(JJ[B)I`: removed `GetPrimitiveArrayCritical`/`ReleasePrimitiveArrayCritical` on the output array; `Final` writes into a local `digestBuf[EVP_MAX_MD_SIZE]` / `digestBuf[ICC_EVP_MAX_MD_SIZE]`, then the context is re-initialised, then `SetByteArrayRegion(output, 0, digestLen, digestBuf)` copies the result. Comments in the code explain the optimization. No Java change.

### Tests run (targeted correctness only; `-Dock.library.path=/ock -Dopenssl.library.path=/openssl`, `OPENSSL_HOME=/openssl`)
- `mvn test -Dtest='TestSHA256*,TestSHA512*,TestMD5,TestSHA1*,TestSHA224*,TestSHA384*,TestSHA3*,TestSHA256Clone_SharedMD,TestAliases,TestTruncatedDigest,TestPBKDF2*,TestHmacSHA*'`: native libraries rebuilt with `-O3 -Werror` (OK); 1266 tests run, 1 failure + 10 errors, 12 skipped. All failures are pre-existing and unrelated (OpenJCEPlusFIPS provider unavailable in the container): `TestTruncatedDigest.testRSASignatureSHA512_224` and the 10 `TestHmacSHA1InteropSunJCE` tests (`no such algorithm: HmacSHA1 for provider OpenJCEPlusFIPS`). All digest/KAT/clone/alias/PBKDF2/HMAC tests that exercise the changed natives (`digest()` after large updates, clone, PKCS12 helper unaffected) pass.
- `mvn checkstyle:checkstyle`: no violations.

### Learnings
- The Jenkins-relevant effect of this change is expected to be tiny (one JNI call per 2048B/32768B op, which take microseconds to milliseconds); it is a strict work reduction for both backends and also shortens the GC-blocking window and removes a latent overflow for short output arrays. It cannot move the headline materially; the 2048B/32768B scores remain bound by the native compression function.
- `GetPrimitiveArrayCritical` stays the cheapest correct pin for the large input (zero copy, no allocation); `GetByteArrayElements`/`GetByteArrayRegion` add an O(n) copy.
- No other removable work exists on the large path in the Java (`Digest`, `MessageDigest`) or JNI layers.

### Ideas NOT Yet Tried
- Unchanged from iterations 5 and 6: Panama `critical(true)` prototype for one algorithm, routing SHA-2 of OCK to the OpenSSL backend on x86_64, ICC CPU-dispatch investigation (SHA-NI/AVX2).
- Drop the unused `&isCopy` argument in `DIGEST_update` (`NULL`), purely cosmetic-level saving.

## Iteration 8 (OpenSSL backend only; OCK untouched)

NO LOCAL MEASUREMENT in this iteration (by instruction): nothing was benchmarked or timed and no performance numbers are recorded. Decisions rest on code reading, `objdump -d` of the system `libcrypto.so.3` (OpenSSL 3.5, aarch64 build in `/openssl/lib`), `objdump -dr` of the freshly compiled `Digest.o`, and cost reasoning. Jenkins x86_64 JMH is the judge.

### Hypotheses and code-analysis reasoning (all four areas of the task)

1. **EVP_MD fetch / re-init / ERR state (no change needed).**
   - `DIGEST_create` is the only place that resolves the algorithm: one explicit `EVP_MD_fetch(NULL, name, NULL)`, then `EVP_DigestInit_ex2(ctx, md, NULL)` (which up-refs the `EVP_MD` into `ctx->fetched_digest`), then our own reference is dropped with `EVP_MD_free`. Contexts are pooled in `base/Digest.java`, so create is not on the per-operation path.
   - The per-operation reset is `EVP_DigestInit_ex2(ctx, NULL, NULL)`. Disassembly of `evp_md_init_internal` (the body of `EVP_DigestInit_ex2`, which is a 2-instruction tail call) confirms what the 3.5 source does for `type == NULL`: it takes `type = ctx->digest`, finds `ctx->engine == NULL` and `ctx->reqdigest == ctx->digest`, skips `ENGINE_*`, skips `EVP_MD_fetch`/`EVP_MD_up_ref`/`EVP_MD_free` (those are only reached when `type != ctx->digest`... the "reuse" branch at `1c8728..1c8814` goes straight to `tail-call digest->dinit(ctx->algctx, params)`). Because the context already has `fetched_digest`, `ctx->algctx` is kept and the provider's `dinit` just re-initialises the hash state. No name/property lookup, no refcount operation, no allocation.
   - Reset path is also free of `ERR_set_mark`/`ERR_pop_to_mark`/`ERR_clear_error`: those exist in `ossl_engine_table_select`, which is only reached through `ENGINE_get_digest_engine` in the *`type != NULL`, no-engine-yet* branch (the branch at `1c8924`). In the `ctx->digest` reuse case with `ctx->engine == NULL` the code still evaluates `ENGINE_get_digest_engine` only when `type` was passed explicitly (`cbz x21` / `ctx->digest` path at `1c8830`..`1c8844` jumps to `1c875c`, i.e. `ENGINE_finish(NULL)`, which is a `cbz x0` early return). The wrapper itself calls no `ERR_*` function on the success path (`throwOSSLException` is only invoked on failure).
   - `EVP_DigestUpdate`, `EVP_DigestFinal_ex`: no atomics/locks on the success path (checked in the disassembly: only the provider function-pointer call, `EVP_MD_CTX_get_size_ex`, flag stores and `OPENSSL_cleanse` of `ctx->md_data`... the cleanse of the algorithm context size on `FINALISE`-less Final is part of the library and cannot be influenced from the wrapper).
   - Rejected idea, already covered: `EVP_Digest`/`EVP_Q_digest`/`copy_ex` template reset (iteration 5).

2. **JNI wrapper per-call work (`openssl/Digest.c`).**
   - Success path of `DIGEST_updateDigestAndReset` / `DIGEST_digest_and_reset` / `DIGEST_update`: one combined NULL/negative parameter check, the EVP calls, the JNI array copies. No mutex, no logging (`debug` macros are not used in this file), no `memset`, no zero-initialised buffers (`digestBuf` and `inBuf` are uninitialised stack arrays), no `dlsym`: the OpenSSL functions are ordinary link-time imports of `libopenjceplus.so` (`-l crypto`), not a function-pointer table.
   - **Found: PLT indirection.** The shared object is built with `-fPIC` and no `-fno-plt`. On x86_64 Linux every call to an imported function (`EVP_DigestUpdate`, `EVP_DigestFinal_ex`, `EVP_DigestInit_ex2`) therefore goes `call <name>@plt` -> `jmp *name@GOT(%rip)` (an extra direct call + an extra indirect jump through a PLT stub, with its own i-cache/BTB entry). With `-fno-plt` GCC/Clang emit `call *name@GOTPCREL(%rip)` straight to the target. On the 16B path that is 3 PLT stubs per operation (Update, Final, Init), on the 2048B/32768B path 2 (Update, then Final+Init in the second JNI call) removed. Verified by compiling the unmodified source with and without `-fno-plt` and diffing `objdump -dr` of `DIGEST_updateDigestAndReset`: without the flag the three calls are `bl EVP_DigestUpdate/Final_ex/Init_ex2` (R_*_CALL26 / on x86_64 R_X86_64_PLT32), with the flag they are loaded from the GOT (`R_AARCH64_ADR_GOT_PAGE`/`LD64_GOT_LO12_NC` here; `R_X86_64_GOTPCRELX` on x86_64). The cold `throwOSSLException` calls are unaffected in cost.
   - Safety of `-fno-plt`: no change in semantics. The imports are resolved at load time (`GLOB_DAT`/`R_X86_64_GLOB_DAT`) instead of lazily on first call; `libcrypto.so.3` is a `DT_NEEDED` dependency of `libopenjceplus.so` so every symbol is available at load time (the library already loads libcrypto before any of our code runs). It is a supported flag in GCC >= 5 and Clang. Applied to x86-linux64 only: that is the platform measured on Jenkins; the other platforms (aarch64, ppc64le, s390x, AIX, z/OS, Mac) have different linkers/ABIs and are left untouched to keep risk at zero. FIPS provider: not affected (the same native library, the same calls; the flag only changes how the calls are encoded).
   - Other flags checked: `-O3` already set (iteration 1); `-fvisibility=hidden`, LTO and `-fno-semantic-interposition` have no effect on the hot path because the wrapper has no intra-library hot calls (`DIGEST_update_internal` and the other helpers are `static inline`); `-fstack-protector` is kept (security; the cost is one canary load/compare per JNI function and removing it would be a security regression, not done).
   - **`isCopy` out-parameter in `DIGEST_update`.** `GetPrimitiveArrayCritical(env, data, &isCopy)` stored into a local that was never read. Passing `NULL` is explicitly allowed by the JNI specification and `DIGEST_updateDigestAndReset` already does it. This removes one stack slot and the VM's store through the pointer for every >256B update (the Idea listed at the end of iteration 7).

3. **EVP_MD_CTX flags (`EVP_MD_CTX_FLAG_ONESHOT`, `FINALISE`) - rejected, nothing to gain.**
   - `EVP_MD_CTX_FLAG_ONESHOT` (0x0008) is a legacy hint that `EVP_DigestUpdate` will be called at most once; in OpenSSL 3.x `EVP_DigestUpdate`/`EVP_DigestFinal_ex` do not read it (the disassembly of both functions above contains no test of bit 3 of `ctx->flags`; the only flag tests are `EVP_MD_CTX_FLAG_FINALISED` (0x800) and `NO_INIT`/`CLEANED`). It was only used by the removed `EVP_MD_CTX_FLAG_ONESHOT` path of the legacy 1.0.x `md_data` allocation for the old SSL3 MD5/SHA1 code. Setting it would be a no-op.
   - `EVP_MD_CTX_FLAG_FINALISE` (0x0800... the flag set by `EVP_DigestFinal_ex` itself, bit 11) is *set by* Final to make a second Final fail (`FINALISED` test in `EVP_DigestUpdate` at `1c8834`); it is cleared again by `evp_md_init_internal` on every re-init (`EVP_MD_CTX_clear_flags(ctx, 0x802)` at `1c8730`). There is no flag that makes Final skip padding/compression work, and it would be incorrect for SHA-3 / XOF-capable digests to try. No change.

4. **Java side of the OpenSSL path (no change needed).**
   - `NativeOpenSSLAdapter.DIGEST_*` are one-line static forwards with the cached `long osslContextId`; no `synchronized`, no allocation, no validation (identical in structure to `NativeOCKAdapter`). `NativeOpenSSLImplementation.DIGEST_*` are plain `static native` methods. `base/Digest.java` is shared with OCK and has already been stripped in iterations 1-6 (no lock, merged update+digest, cached context ids, no allocation but the API-mandated result array). There is no OpenSSL-only wrapper layer left to remove. FIPS: `FIPS`/`NonFIPS` adapter subclasses share the same forwards; unchanged.

### Exact changes
1. `src/main/native/openssl/openjceplus.mak`: after `include ../share/common.mak`, `CFLAGS += -fno-plt` when `PLATFORM` is `x86-linux64` (comment in the file explains it; it has to follow the include because `common.mak` assigns `CFLAGS=`). Confirmed with `make displaycompiler` that the flag appears for `x86-linux64` (`CFLAGS: -O3 -fPIC -Werror -std=gnu99 -pedantic -Wall -fstack-protector -DLINUX -m64 -fno-plt`) and does not appear for `arm-linux64`. The OCK makefile (`ock/jgskit.mak`) and the shared `common.mak` are untouched.
2. `src/main/native/openssl/Digest.c`, `DIGEST_update`: removed the unused `jboolean isCopy` local and passed `NULL` as the `isCopy` argument of `GetPrimitiveArrayCritical` (comment in code).

Not changed (analysed, nothing strictly removable): reset call (`EVP_DigestInit_ex2(ctx, NULL, NULL)` is already the cheapest correct form), EVP_MD fetch caching, error-queue handling, EVP_MD_CTX flags, Java adapter layer.

### Why these strictly remove work and are safe
- `-fno-plt`: removes one `call`+`jmp *GOT` hop per imported function call; adds nothing at runtime (the GOT slot load is the same load the PLT stub did). Only load-time symbol binding changes. On a platform where the toolchain does not support it the build would fail loudly (`-Werror` unknown-option) rather than silently misbehave; GCC (Jenkins x86_64 uses gcc) supports it. No behavioural, security, thread-safety, Cleaner or FIPS impact.
- `isCopy -> NULL`: the value was never read; JNI explicitly permits `NULL`. Pinning behaviour, `JNI_ABORT` release and context state are unchanged.

### Tests run (targeted correctness only; `-Dock.library.path=/ock -Dopenssl.library.path=/openssl`, `OPENSSL_HOME=/openssl`)
- `mvn test -Dtest='TestSHA256*,TestSHA512*,TestMD5,TestSHA1*,TestSHA224*,TestSHA384*,TestSHA3*,TestSHA256Clone_SharedMD,TestAliases,TestTruncatedDigest'`: native OpenSSL library rebuilt with `-O3 -Werror` (OK; the container is aarch64, so the `-fno-plt` branch of the makefile is not exercised here - it was verified only by `make displaycompiler` and by compiling `Digest.c` with `-fno-plt -Werror` on aarch64 to prove the flag is accepted and the calls become GOT loads); 705 tests run, 1 failure, 0 errors, 12 skipped. The single failure is the known pre-existing `TestTruncatedDigest.testRSASignatureSHA512_224` (OpenJCEPlusFIPS provider unavailable in the container).
- `mvn checkstyle:checkstyle`: BUILD SUCCESS.

### Learnings
- Reset and fetch handling in the OpenSSL backend was already optimal; the only remaining per-call cost attributable to our build configuration was PLT indirection on the three EVP calls (x86_64), which was never addressed because the shared flags set only `-O3 -fPIC`.
- Expect this change to be tiny (a few cycles per EVP call, highest relative share at 16B, none at 32768B) and probably within Jenkins noise; it is a strict reduction of executed instructions with no semantic change.
- `EVP_MD_CTX` flags offer no work-skipping lever in OpenSSL 3.x for Update/Final.

### Ideas NOT Yet Tried
- Unchanged from iterations 5-7: Panama `critical(true)` prototype for one algorithm, routing SHA-2 of OCK to the OpenSSL backend on x86_64, ICC CPU-dispatch investigation.
- Link the OpenSSL wrapper with `-Wl,-z,now` / `-Wl,-O1,--hash-style=gnu` (no hot-path effect, not pursued) or statically link libcrypto.a (`/openssl/lib/libcrypto.a` exists) so calls become direct `call` instructions; this changes deployment/FIPS provider loading semantics and needs an owner decision.
