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

## Optimization Parameters
- Repository: OPENJCEPLUS
- Branch: perf-opt-messagedigest-20261106-143220 (created from upstream/java25)
- Max Iterations: 10
- Regression Threshold: 1% drop of headline score vs best-so-far (per provider)
- Note: baseline has large noise (scoreError up to +-50% on some 16B/2048B cases); judge on the headline geomean and on payloadSize 16 (JNI/call overhead dominated) vs 32768 (native dominated) separately.

## Baseline Scores (ops/s), columns payload 16 / 2048 / 32768
| Benchmark method | OCK | OpenSSL |
|---|---|---|
| sha512UpdateDigest | 2325553 / 189334 / 14931 | 2391988 / 285702 / 20662 |
| sha512SingleShotDigest | 2000677 / 217021 / 14987 | 2579267 / 294728 / 20680 |
| md5SingleShotDigest | 4378990 / 316468 / 21364 | 4349339 / 335274 / 22577 |
| sha512_224UpdateDigest | 2378458 / 210824 / 12798 | 2594220 / 295509 / 18283 |
| sha512_256UpdateDigest | 2196947 / 217790 / 14986 | 2629171 / 295265 / 20650 |
| md5UpdateDigest | 4346669 / 319816 / 21372 | 4333819 / 333205 / 22463 |
| sha256UpdateDigest | 2722196 / 176460 / 10241 | 2632624 / 206058 / 11578 |
| sha1SingleShotDigest | 4286429 / 361930 / 25879 | 4175881 / 435973 / 30084 |
| sha1UpdateDigest | 4306765 / 352969 / 23980 | 3992695 / 433131 / 28256 |
| sha256SingleShotDigest | 2979387 / 180572 / 11927 | 3059962 / 208278 / 12685 |

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

## Best Performing State
- Iteration: 1
- Headline OCK: 247801.6, OpenSSL: 285058.0
- Commit Hash: 6299cc6adbf7ef0d78d7002cb1b955f1ccab0bd0
- Build UUID: 6718831d-747c-4d01-88b7-42df64d1301b

## Next Steps
- Iteration 2: the remaining gap to +40% is large (about +30% more per provider), so target larger structural overheads rather than micro-tuning. Highest-impact candidate from the "ideas not yet tried" in notes/optimization_notes.md: add a single-shot JNI entry point (e.g. DIGEST_digestSingleShot(contextId, digestAlgo, data, offset, len, output, outOffset)) that does update + final + reset in ONE JNI crossing, with the digest written directly into the caller's output array, so a single-shot digest(byte[]) drops from 2 native calls (DIGEST_update + DIGEST_digest_and_reset) to 1 and avoids the per-call result byte[] allocation. Pair this with (a) using GetPrimitiveArrayCritical/JNI_ABORT consistently (or direct/off-heap buffers) to avoid JNI array copy mode for 2048B/32768B inputs, (b) reusing a per-instance output buffer and avoiding per-call object allocation in the engine, (c) lighter-weight context reset (e.g. re-init only, no free/alloc) in the JNI layer, and (d) for update-heavy streaming, checking whether the existing DIGEST_updateFastJNI / direct-buffer path can be used from the byte[] update path. Also investigate whether the large-payload sha2 gap between OCK and OpenSSL (32768B) is due to the native build/algorithm selection (e.g. OCK's SHA-2 implementation without SHA-NI/AVX2 acceleration, or non-optimized native build flags in the bundled OCK libs) by checking which library/CPU features are used, since that is outside the Java/JNI layer and may need a different approach.
