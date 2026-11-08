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
