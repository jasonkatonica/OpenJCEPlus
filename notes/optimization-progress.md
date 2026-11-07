# Performance Optimization Progress

## Baseline Measurement
- Benchmark: ibm.jceplus.jmh.MessageDigestBenchmark (10 methods x payloadSize 16/2048/32768 x providers OpenJCEPlus-OCK and OpenJCEPlus-OpenSSL = 60 combinations)
- Java Version: java25 (25.0.5.0.3, openj9-0.63.0)
- Platform: x86_64_linux
- Headline metric: geometric mean of the 30 score values (ops/s, mode thrpt) per provider
- Baseline headline score OCK: 230905.8 ops/s
- Baseline headline score OpenSSL: 268320.6 ops/s
- Target (+40%): OCK 323268 ops/s, OpenSSL 375649 ops/s (BOTH providers should improve by 40% headline-wise)
- Baseline Build UUID: 5bdbcec5-355a-4acc-a87a-ed51d54dbf86
- Baseline Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/107/

## Score History (all individual results, ops/s)
One row per individual result (benchmark method x payloadSize x provider). A new column pair is added after every iteration; headline geomean rows are at the bottom. Delta is vs the iteration 0 baseline.

| Benchmark method | Payload | Provider | Iter 0 baseline | Iter 1 | Δ iter1 vs baseline |
|---|---|---|---|---|---|
| sha512UpdateDigest | 16 | OCK | 2325553 | 2478580 | +6.6% |
| sha512UpdateDigest | 2048 | OCK | 189334 | 219266 | +15.8% |
| sha512UpdateDigest | 32768 | OCK | 14931 | 15030 | +0.7% |
| sha512SingleShotDigest | 16 | OCK | 2000677 | 2473122 | +23.6% |
| sha512SingleShotDigest | 2048 | OCK | 217021 | 218848 | +0.8% |
| sha512SingleShotDigest | 32768 | OCK | 14987 | 14971 | -0.1% |
| md5SingleShotDigest | 16 | OCK | 4378990 | 4909901 | +12.1% |
| md5SingleShotDigest | 2048 | OCK | 316468 | 321401 | +1.6% |
| md5SingleShotDigest | 32768 | OCK | 21364 | 21528 | +0.8% |
| sha512_224UpdateDigest | 16 | OCK | 2378458 | 2555090 | +7.4% |
| sha512_224UpdateDigest | 2048 | OCK | 210824 | 219635 | +4.2% |
| sha512_224UpdateDigest | 32768 | OCK | 12798 | 14992 | +17.1% |
| sha512_256UpdateDigest | 16 | OCK | 2196947 | 2572674 | +17.1% |
| sha512_256UpdateDigest | 2048 | OCK | 217790 | 219515 | +0.8% |
| sha512_256UpdateDigest | 32768 | OCK | 14986 | 15026 | +0.3% |
| md5UpdateDigest | 16 | OCK | 4346669 | 4826728 | +11.0% |
| md5UpdateDigest | 2048 | OCK | 319816 | 321076 | +0.4% |
| md5UpdateDigest | 32768 | OCK | 21372 | 21497 | +0.6% |
| sha256UpdateDigest | 16 | OCK | 2722196 | 3438296 | +26.3% |
| sha256UpdateDigest | 2048 | OCK | 176460 | 181265 | +2.7% |
| sha256UpdateDigest | 32768 | OCK | 10241 | 11967 | +16.9% |
| sha1SingleShotDigest | 16 | OCK | 4286429 | 4745368 | +10.7% |
| sha1SingleShotDigest | 2048 | OCK | 361930 | 370026 | +2.2% |
| sha1SingleShotDigest | 32768 | OCK | 25879 | 26511 | +2.4% |
| sha1UpdateDigest | 16 | OCK | 4306765 | 4867678 | +13.0% |
| sha1UpdateDigest | 2048 | OCK | 352969 | 369443 | +4.7% |
| sha1UpdateDigest | 32768 | OCK | 23980 | 26553 | +10.7% |
| sha256SingleShotDigest | 16 | OCK | 2979387 | 3448250 | +15.7% |
| sha256SingleShotDigest | 2048 | OCK | 180572 | 181640 | +0.6% |
| sha256SingleShotDigest | 32768 | OCK | 11927 | 11983 | +0.5% |
| sha512UpdateDigest | 16 | OpenSSL | 2391988 | 2554807 | +6.8% |
| sha512UpdateDigest | 2048 | OpenSSL | 285702 | 298257 | +4.4% |
| sha512UpdateDigest | 32768 | OpenSSL | 20662 | 20731 | +0.3% |
| sha512SingleShotDigest | 16 | OpenSSL | 2579267 | 2768196 | +7.3% |
| sha512SingleShotDigest | 2048 | OpenSSL | 294728 | 298339 | +1.2% |
| sha512SingleShotDigest | 32768 | OpenSSL | 20680 | 20764 | +0.4% |
| md5SingleShotDigest | 16 | OpenSSL | 4349339 | 4904280 | +12.8% |
| md5SingleShotDigest | 2048 | OpenSSL | 335274 | 337803 | +0.8% |
| md5SingleShotDigest | 32768 | OpenSSL | 22577 | 22638 | +0.3% |
| sha512_224UpdateDigest | 16 | OpenSSL | 2594220 | 2767051 | +6.7% |
| sha512_224UpdateDigest | 2048 | OpenSSL | 295509 | 298150 | +0.9% |
| sha512_224UpdateDigest | 32768 | OpenSSL | 18283 | 20743 | +13.5% |
| sha512_256UpdateDigest | 16 | OpenSSL | 2629171 | 2801300 | +6.5% |
| sha512_256UpdateDigest | 2048 | OpenSSL | 295265 | 296901 | +0.6% |
| sha512_256UpdateDigest | 32768 | OpenSSL | 20650 | 20741 | +0.4% |
| md5UpdateDigest | 16 | OpenSSL | 4333819 | 4845673 | +11.8% |
| md5UpdateDigest | 2048 | OpenSSL | 333205 | 334457 | +0.4% |
| md5UpdateDigest | 32768 | OpenSSL | 22463 | 22630 | +0.7% |
| sha256UpdateDigest | 16 | OpenSSL | 2632624 | 3476853 | +32.1% |
| sha256UpdateDigest | 2048 | OpenSSL | 206058 | 208009 | +0.9% |
| sha256UpdateDigest | 32768 | OpenSSL | 11578 | 13937 | +20.4% |
| sha1SingleShotDigest | 16 | OpenSSL | 4175881 | 4715926 | +12.9% |
| sha1SingleShotDigest | 2048 | OpenSSL | 435973 | 443732 | +1.8% |
| sha1SingleShotDigest | 32768 | OpenSSL | 30084 | 30529 | +1.5% |
| sha1UpdateDigest | 16 | OpenSSL | 3992695 | 4561486 | +14.2% |
| sha1UpdateDigest | 2048 | OpenSSL | 433131 | 442496 | +2.2% |
| sha1UpdateDigest | 32768 | OpenSSL | 28256 | 30572 | +8.2% |
| sha256SingleShotDigest | 16 | OpenSSL | 3059962 | 3492679 | +14.1% |
| sha256SingleShotDigest | 2048 | OpenSSL | 208278 | 209229 | +0.5% |
| sha256SingleShotDigest | 32768 | OpenSSL | 12685 | 13921 | +9.7% |
| **HEADLINE geomean** | all | OCK | 230905.8 | 247801.6 | +7.32% |
| **HEADLINE geomean** | all | OpenSSL | 268320.8 | 285058.0 | +6.24% |

## Optimization Parameters
- Repository: OPENJCEPLUS
- Branch: perf-opt-messagedigest-20261106-143220 (created from upstream/java25)
- Max Iterations: 10
- Regression Threshold: 1% drop of headline score vs best-so-far (per provider)
- Note: baseline has large noise (scoreError up to +-50% on some 16B/2048B cases); judge on the headline geomean and on payloadSize 16 (JNI/call overhead dominated) vs 32768 (native dominated) separately.
- Reporting convention: Every iteration records (a) all 60 individual scores plus delta vs baseline and vs previous iteration in Score History / the iteration entry, and (b) the headline geomean per provider.

## Iteration History

### Iteration 0: Baseline
- Status: COMPLETE
- Headline OCK: 230905.8 ops/s, OpenSSL: 268320.6 ops/s
- Improvement: 0%
- Build UUID: 5bdbcec5-355a-4acc-a87a-ed51d54dbf86
- Notes: Initial baseline measurement

### Iteration 1: Remove Java-side per-call overhead (no synchronized, context caching/precomputed lengths for all 12 algorithms, cached native context IDs, direct engineDigest(byte[],int,int)) and tune the JNI layer (-O3, JNI_ABORT on read-only update, inlined helpers)
- Status: COMPLETE
- Headline (geomean of 30 scores per provider): OCK 247801.6 ops/s, OpenSSL 285058.0 ops/s
- Improvement vs baseline: OCK +7.32%, OpenSSL +6.24% (target +40% each)
- Per payload improvement vs baseline (geomean over the 10 methods): OCK 16B +14.2%, 2048B +3.3%, 32768B +4.8%; OpenSSL 16B +12.3%, 2048B +1.3%, 32768B +5.3%
- Individual results: see the Score History table (column Iter 1 and its delta vs baseline)
- Notable per-method changes: sha256 16B OCK 2722196->3438296 (+26%), OpenSSL 2632624->3476853 (+32%); sha256 32768B OpenSSL 11578->13937 (+20%); sha512SingleShot 16B OCK 2000677->2473122 (+24%); md5/sha1 16B about +10-13%; sha512 family 2048B OCK about +16-17% (189334/217021/210824/217790 -> ~219000); 2048B and 32768B for md5/sha1 are essentially flat (native-bound)
- Build UUID: 6718831d-747c-4d01-88b7-42df64d1301b
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/108/
- Bob Shell UUID: 0f777511-c614-4fea-bca3-13db2d542e73
- Commit Hash: 6299cc6adbf7ef0d78d7002cb1b955f1ccab0bd0
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/6299cc6adbf7ef0d78d7002cb1b955f1ccab0bd0
- Files Changed: 11
- Lines Added/Removed: 216/130
- Result: SUCCESS (improvement, no regression)
- Notes: The gain is mostly Java-side overhead removal (monitor enter/exit on update/digest/reset, native DIGEST_size and context reallocation for MD5/SHA-512/224/SHA-512/256/SHA3 that were not cached, getId() indirection, temp byte[] + arraycopy in engineDigest(byte[],int,int)); the -O3 and JNI_ABORT changes only affect the thin JNI wrapper, not the hashing code inside the OCK/OpenSSL libraries, so they cannot speed up native hashing itself. Gains concentrate at small payloads (16B, per-call overhead dominated) while large payloads stay bounded by native hashing speed (OCK sha2 32768B is still ~15-25% slower than OpenSSL). The noise level of this run is lower than the baseline (many scoreErrors < 2%), so these deltas are more trustworthy than the baseline comparison suggests.

### Iteration 2: Merge small update + digest into one JNI call (DIGEST_updateDigestAndReset) and buffer small inputs in Java
- Status: CODE COMMITTED, benchmark pending
- Bob Shell UUID: a1c01b71-47f0-4122-9177-855a821972db
- Commit Hash: ce6aa00d9b60f1816207a541ef2cd4af2626740a
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/ce6aa00d9b60f1816207a541ef2cd4af2626740a
- Files Changed: 9
- Lines Added/Removed: 318/14
- Approach: For small payloads, cost is dominated by JNI crossings and critical-array pin/unpin. Added DIGEST_updateDigestAndReset to combine update + final + re-init in one JNI crossing for OCK and OpenSSL. In Digest.java, updates <=256B are buffered in a per-instance pending array and flushed together with the final digest call, reducing JNI crossings from 2 to 1 and eliminating critical array pin/unpin for small payloads. Larger updates flush pending data and go directly to native.
- Tests run (targeted): -Dtest='TestSHA*,TestMD5,TestTruncatedDigest,TestAliases,TestSHA256Clone_SharedMD,TestECDSASignatureInterop*,TestRSASignatureInterop*,TestHmacSHA*,TestHKDF*,TestPBKDF2*' (1386 tests, 1 failure + 10 errors, all pre-existing: TestTruncatedDigest.testRSASignatureSHA512_224 and TestHmacSHA1InteropSunJCE due to OpenJCEPlusFIPS provider not available in this container; all SHA/MD5/KAT/clone/alias pass), ad-hoc differential fuzz vs SUN provider (60000 digests match), checkstyle:checkstyle BUILD SUCCESS
- Result: PENDING (Jenkins benchmark to be run)

## Best Performing State
- Iteration: 1
- Headline OCK: 247801.6, OpenSSL: 285058.0
- Commit Hash: 6299cc6adbf7ef0d78d7002cb1b955f1ccab0bd0
- Build UUID: 6718831d-747c-4d01-88b7-42df64d1301b

## Next Steps
- Iteration 2: the remaining gap to +40% is large (about +30% more per provider), so target larger structural overheads rather than micro-tuning. Highest-impact candidate from the "ideas not yet tried" in notes/optimization_notes.md: add a single-shot JNI entry point (e.g. DIGEST_digestSingleShot(contextId, digestAlgo, data, offset, len, output, outOffset)) that does update + final + reset in ONE JNI crossing, with the digest written directly into the caller's output array, so a single-shot digest(byte[]) drops from 2 native calls (DIGEST_update + DIGEST_digest_and_reset) to 1 and avoids the per-call result byte[] allocation. Pair this with (a) using GetPrimitiveArrayCritical/JNI_ABORT consistently (or direct/off-heap buffers) to avoid JNI array copy mode for 2048B/32768B inputs, (b) reusing a per-instance output buffer and avoiding per-call object allocation in the engine, (c) lighter-weight context reset (e.g. re-init only, no free/alloc) in the JNI layer, and (d) for update-heavy streaming, checking whether the existing DIGEST_updateFastJNI / direct-buffer path can be used from the byte[] update path. Also investigate whether the large-payload sha2 gap between OCK and OpenSSL (32768B) is due to the native build/algorithm selection (e.g. OCK's SHA-2 implementation without SHA-NI/AVX2 acceleration, or non-optimized native build flags in the bundled OCK libs) by checking which library/CPU features are used, since that is outside the Java/JNI layer and may need a different approach.
