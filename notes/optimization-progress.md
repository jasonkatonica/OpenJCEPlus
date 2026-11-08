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
One row per individual result (benchmark method x payloadSize x provider). A new column is added after every iteration; Δ columns are vs the iteration 0 baseline and vs the previous iteration. Headline geomean rows are at the bottom. Iteration 3 made no code change and was not benchmarked (equals Iter 2).

| Benchmark method | Payload | Provider | Iter 0 baseline | Iter 1 | Iter 2 | Iter 4 | Δ iter4 vs baseline | Δ iter4 vs iter2 |
|---|---|---|---|---|---|---|---|---|
| sha512UpdateDigest | 16 | OCK | 2325553 | 2478580 | 2560354 | 2576312 | +10.8% | +0.6% |
| sha512UpdateDigest | 2048 | OCK | 189334 | 219266 | 218717 | 219201 | +15.8% | +0.2% |
| sha512UpdateDigest | 32768 | OCK | 14931 | 15030 | 14937 | 15007 | +0.5% | +0.5% |
| sha512SingleShotDigest | 16 | OCK | 2000677 | 2473122 | 2461462 | 2534667 | +26.7% | +3.0% |
| sha512SingleShotDigest | 2048 | OCK | 217021 | 218848 | 218661 | 219390 | +1.1% | +0.3% |
| sha512SingleShotDigest | 32768 | OCK | 14987 | 14971 | 15005 | 15024 | +0.2% | +0.1% |
| md5SingleShotDigest | 16 | OCK | 4378990 | 4909901 | 5476106 | 5537735 | +26.5% | +1.1% |
| md5SingleShotDigest | 2048 | OCK | 316468 | 321401 | 322400 | 322106 | +1.8% | -0.1% |
| md5SingleShotDigest | 32768 | OCK | 21364 | 21528 | 21530 | 21513 | +0.7% | -0.1% |
| sha512_224UpdateDigest | 16 | OCK | 2378458 | 2555090 | 2693502 | 2671610 | +12.3% | -0.8% |
| sha512_224UpdateDigest | 2048 | OCK | 210824 | 219635 | 219715 | 219465 | +4.1% | -0.1% |
| sha512_224UpdateDigest | 32768 | OCK | 12798 | 14992 | 15020 | 15026 | +17.4% | +0.0% |
| sha512_256UpdateDigest | 16 | OCK | 2196947 | 2572674 | 2694286 | 2638127 | +20.1% | -2.1% |
| sha512_256UpdateDigest | 2048 | OCK | 217790 | 219515 | 219305 | 219767 | +0.9% | +0.2% |
| sha512_256UpdateDigest | 32768 | OCK | 14986 | 15026 | 15036 | 14986 | +0.0% | -0.3% |
| md5UpdateDigest | 16 | OCK | 4346669 | 4826728 | 5550417 | 5480375 | +26.1% | -1.3% |
| md5UpdateDigest | 2048 | OCK | 319816 | 321076 | 322481 | 322124 | +0.7% | -0.1% |
| md5UpdateDigest | 32768 | OCK | 21372 | 21497 | 21497 | 21525 | +0.7% | +0.1% |
| sha256UpdateDigest | 16 | OCK | 2722196 | 3438296 | 3676474 | 3691053 | +35.6% | +0.4% |
| sha256UpdateDigest | 2048 | OCK | 176460 | 181265 | 181001 | 181851 | +3.1% | +0.5% |
| sha256UpdateDigest | 32768 | OCK | 10241 | 11967 | 11970 | 11975 | +16.9% | +0.0% |
| sha1SingleShotDigest | 16 | OCK | 4286429 | 4745368 | 5351120 | 5413551 | +26.3% | +1.2% |
| sha1SingleShotDigest | 2048 | OCK | 361930 | 370026 | 370362 | 370524 | +2.4% | +0.0% |
| sha1SingleShotDigest | 32768 | OCK | 25879 | 26511 | 26476 | 26538 | +2.5% | +0.2% |
| sha1UpdateDigest | 16 | OCK | 4306765 | 4867678 | 5345373 | 5375425 | +24.8% | +0.6% |
| sha1UpdateDigest | 2048 | OCK | 352969 | 369443 | 370259 | 370804 | +5.1% | +0.1% |
| sha1UpdateDigest | 32768 | OCK | 23980 | 26553 | 26547 | 26547 | +10.7% | +0.0% |
| sha256SingleShotDigest | 16 | OCK | 2979387 | 3448250 | 3648478 | 3665655 | +23.0% | +0.5% |
| sha256SingleShotDigest | 2048 | OCK | 180572 | 181640 | 181507 | 181198 | +0.3% | -0.2% |
| sha256SingleShotDigest | 32768 | OCK | 11927 | 11983 | 11994 | 11972 | +0.4% | -0.2% |
| sha512UpdateDigest | 16 | OpenSSL | 2391988 | 2554807 | 2820343 | 2861006 | +19.6% | +1.4% |
| sha512UpdateDigest | 2048 | OpenSSL | 285702 | 298257 | 297299 | 296112 | +3.6% | -0.4% |
| sha512UpdateDigest | 32768 | OpenSSL | 20662 | 20731 | 20754 | 20720 | +0.3% | -0.2% |
| sha512SingleShotDigest | 16 | OpenSSL | 2579267 | 2768196 | 2826857 | 2764887 | +7.2% | -2.2% |
| sha512SingleShotDigest | 2048 | OpenSSL | 294728 | 298339 | 297356 | 297756 | +1.0% | +0.1% |
| sha512SingleShotDigest | 32768 | OpenSSL | 20680 | 20764 | 20770 | 20784 | +0.5% | +0.1% |
| md5SingleShotDigest | 16 | OpenSSL | 4349339 | 4904280 | 5287648 | 5296602 | +21.8% | +0.2% |
| md5SingleShotDigest | 2048 | OpenSSL | 335274 | 337803 | 338837 | 338551 | +1.0% | -0.1% |
| md5SingleShotDigest | 32768 | OpenSSL | 22577 | 22638 | 22638 | 22654 | +0.3% | +0.1% |
| sha512_224UpdateDigest | 16 | OpenSSL | 2594220 | 2767051 | 2852481 | 2900991 | +11.8% | +1.7% |
| sha512_224UpdateDigest | 2048 | OpenSSL | 295509 | 298150 | 297892 | 298756 | +1.1% | +0.3% |
| sha512_224UpdateDigest | 32768 | OpenSSL | 18283 | 20743 | 20752 | 20744 | +13.5% | -0.0% |
| sha512_256UpdateDigest | 16 | OpenSSL | 2629171 | 2801300 | 2897696 | 2883792 | +9.7% | -0.5% |
| sha512_256UpdateDigest | 2048 | OpenSSL | 295265 | 296901 | 298706 | 297976 | +0.9% | -0.2% |
| sha512_256UpdateDigest | 32768 | OpenSSL | 20650 | 20741 | 20747 | 20603 | -0.2% | -0.7% |
| md5UpdateDigest | 16 | OpenSSL | 4333819 | 4845673 | 5244805 | 5295264 | +22.2% | +1.0% |
| md5UpdateDigest | 2048 | OpenSSL | 333205 | 334457 | 338136 | 338945 | +1.7% | +0.2% |
| md5UpdateDigest | 32768 | OpenSSL | 22463 | 22630 | 22615 | 22620 | +0.7% | +0.0% |
| sha256UpdateDigest | 16 | OpenSSL | 2632624 | 3476853 | 3652157 | 3650081 | +38.6% | -0.1% |
| sha256UpdateDigest | 2048 | OpenSSL | 206058 | 208009 | 209875 | 209937 | +1.9% | +0.0% |
| sha256UpdateDigest | 32768 | OpenSSL | 11578 | 13937 | 13907 | 13931 | +20.3% | +0.2% |
| sha1SingleShotDigest | 16 | OpenSSL | 4175881 | 4715926 | 5287499 | 5321688 | +27.4% | +0.6% |
| sha1SingleShotDigest | 2048 | OpenSSL | 435973 | 443732 | 443808 | 443764 | +1.8% | -0.0% |
| sha1SingleShotDigest | 32768 | OpenSSL | 30084 | 30529 | 30492 | 30575 | +1.6% | +0.3% |
| sha1UpdateDigest | 16 | OpenSSL | 3992695 | 4561486 | 5191979 | 5221873 | +30.8% | +0.6% |
| sha1UpdateDigest | 2048 | OpenSSL | 433131 | 442496 | 443836 | 443123 | +2.3% | -0.2% |
| sha1UpdateDigest | 32768 | OpenSSL | 28256 | 30572 | 30525 | 30056 | +6.4% | -1.5% |
| sha256SingleShotDigest | 16 | OpenSSL | 3059962 | 3492679 | 3678623 | 3684790 | +20.4% | +0.2% |
| sha256SingleShotDigest | 2048 | OpenSSL | 208278 | 209229 | 208741 | 209985 | +0.8% | +0.6% |
| sha256SingleShotDigest | 32768 | OpenSSL | 12685 | 13921 | 13964 | 13917 | +9.7% | -0.3% |
| **HEADLINE geomean** | all | OCK | 230905.8 | 247801.6 | 253782.2 | 254158.6 | +10.07% | +0.15% |
| **HEADLINE geomean** | all | OpenSSL | 268320.8 | 285058.0 | 291841.4 | 291946.7 | +8.81% | +0.04% |

Aggregate summary (geomean over the 10 methods, per payload size):
- OCK: 16B +23.0% vs baseline (+0.3% vs iter2); 2048B +3.4% (+0.1%); 32768B +4.8% (+0.0%)
- OpenSSL: 16B +20.6% vs baseline (+0.3% vs iter2); 2048B +1.6% (+0.0%); 32768B +5.1% (-0.2%)

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
- Status: COMPLETE
- Headline (geomean of 30 scores per provider): OCK 253782.2 ops/s, OpenSSL 291841.4 ops/s
- Improvement vs baseline: OCK +9.91%, OpenSSL +8.77% (target +40% each)
- Change vs previous iteration (iter 1): OCK +2.41%, OpenSSL +2.38%
- Individual results: see the Score History table (columns Iter 2, Δ iter2 vs baseline, Δ iter2 vs iter1)
- Build UUID: 987b76c2-0dc8-4b0c-ab56-f508321b2954
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/109/
- Bob Shell UUID: a1c01b71-47f0-4122-9177-855a821972db
- Commit Hash: ce6aa00d9b60f1816207a541ef2cd4af2626740a
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/ce6aa00d9b60f1816207a541ef2cd4af2626740a
- Files Changed: 9
- Lines Added/Removed: 318/14
- Approach: For small payloads, cost is dominated by JNI crossings and critical-array pin/unpin. Added DIGEST_updateDigestAndReset to combine update + final + re-init in one JNI crossing for OCK and OpenSSL. In Digest.java, updates <=256B are buffered in a per-instance pending array and flushed together with the final digest call, reducing JNI crossings from 2 to 1 and eliminating critical array pin/unpin for small payloads. Larger updates flush pending data and go directly to native.
- Tests run (targeted): -Dtest='TestSHA*,TestMD5,TestTruncatedDigest,TestAliases,TestSHA256Clone_SharedMD,TestECDSASignatureInterop*,TestRSASignatureInterop*,TestHmacSHA*,TestHKDF*,TestPBKDF2*' (1386 tests, 1 failure + 10 errors, all pre-existing: TestTruncatedDigest.testRSASignatureSHA512_224 and TestHmacSHA1InteropSunJCE due to OpenJCEPlusFIPS provider not available in this container; all SHA/MD5/KAT/clone/alias pass), ad-hoc differential fuzz vs SUN provider (60000 digests match), checkstyle:checkstyle BUILD SUCCESS
- Result: SUCCESS (improvement, no regression; no individual score dropped more than -0.6% which is within noise)
- Notes: gain is entirely at payload 16B (md5/sha1 +8% to +15% vs iter1, sha512/sha256 +2% to +10%); payloads 2048B and 32768B are unchanged vs iteration 1 (they are bound by native hash speed, not per-call overhead). OCK is still ~26-36% slower than OpenSSL for SHA-2 at 2048B and 32768B (e.g. sha512 2048B OCK 218717 vs OpenSSL 297299; sha256 32768B OCK 11970 vs OpenSSL 13907) and that is now the biggest remaining OCK-specific gap. For OpenSSL the 2048B/32768B scores are essentially at native speed. Headline geomean is mathematically limited because 20 of the 30 scores per provider (2048B, 32768B) cannot be improved by call-overhead removal.

### Iteration 3: Large-payload (2048B/32768B) byte-path analysis; no code change (2KB single-call experiment measured and reverted)
- Status: COMPLETE (analysis only, source tree identical to iteration 2)
- Bob Shell UUID: 5ae67dfc-606d-49b5-a245-4dba698d436a
- Commit Hash: fb276419a0c9d2b9da78fef94b1b20ce65440512 (notes only)
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/fb276419a0c9d2b9da78fef94b1b20ce65440512
- Files Changed: 1 (notes/optimization_notes.md)
- Benchmark: NOT RUN (code identical to iteration 2, so scores equal Iteration 2: OCK 253782.2, OpenSSL 291841.4 headline; no Jenkins build needed)
- Result: NO_CHANGE
- Findings:
  - Path is one pinned zero-copy native update call per payload with no Java-side chunking/copy/zero-fill; JNI array access does not copy (isCopy==false verified).
  - Time is linear in bytes so 2048B/32768B are bound by the native compression function.
  - On aarch64 OCK and OpenSSL SHA-2 are the same speed, the 26-36% x86_64 OCK SHA-2 gap on Jenkins is in the native ICC library/CPU dispatch and is not visible in the Java/JNI path.
  - The experiment of raising the pending buffer from 256B to 2048B to merge into one JNI call was 2.5-8.7% SLOWER at 2048B and was reverted.
- Notes: 20 of 30 scores per provider (2048B, 32768B) are native-bound, so the +40% headline target is not reachable by Java/JNI work alone; remaining levers are the 16B per-call overhead (headline ceiling about +14.5% even if the 10 16B scores improved another 50%) and decisions outside this code (routing SHA-2 to the OpenSSL backend, newer ICC build/CPU dispatch on x86_64).

### Iteration 4: Drop redundant GetArrayLength JNI call in DIGEST_updateDigestAndReset (OCK + OpenSSL native Digest.c)
- Status: COMPLETE
- Headline (geomean of 30 scores per provider): OCK 254158.6 ops/s, OpenSSL 291946.7 ops/s
- Improvement vs baseline: OCK +10.07%, OpenSSL +8.81% (target +40% each)
- Change vs previous best (iter 2): OCK +0.15%, OpenSSL +0.04% (within run-to-run noise)
- Individual results: see Score History (columns Iter 4, Δ iter4 vs baseline, Δ iter4 vs iter2). Largest individual moves vs iter2 are noise-level: best sha512SingleShot OCK 16B +3.0%, worst sha512SingleShot OpenSSL 16B -2.2% (scoreErrors on those cases were up to +-10%).
- Bob Shell UUID: 4cc5f5ed-75e6-45b0-b1e4-2f0e916bb9d7
- Commit Hash: 1b6f7bf160f7acfc1fa785415e3e6a0827b0aed3
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/1b6f7bf160f7acfc1fa785415e3e6a0827b0aed3
- Build UUID: 152e81f4-266c-421c-a1d2-7f3284f738a6
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/110/
- Files Changed: 3 (src/main/native/ock/Digest.c, src/main/native/openssl/Digest.c, notes/optimization_notes.md)
- Lines Added/Removed: 54/9
- Tests run (targeted): -Dtest='TestSHA256*,TestSHA512*,TestMD5,TestSHA1*,TestSHA224*,TestSHA384*,TestSHA3*,TestSHA256Clone_SharedMD,TestAliases,TestTruncatedDigest' (705 run, 1 failure, 0 errors, 12 skipped; the only failure is the pre-existing TestTruncatedDigest.testRSASignatureSHA512_224 because the OpenJCEPlusFIPS provider is not available in the container), mvn clean compile BUILD SUCCESS (-O3 -Werror), mvn checkstyle:checkstyle BUILD SUCCESS
- Result: NO_CHANGE (measured gain is within noise, as the local A/B predicted about +1% at 16B at most; no regression)
- Notes: The redundant GetArrayLength was removed because SetByteArrayRegion already bounds-checks (followed by ExceptionCheck). Local A/B on aarch64 showed about +1.2% (OCK) and +0.7-1.0% (OpenSSL) at 16B only, nothing at 2048B/32768B. Analysis showed the Java/JNI layer is within ~10 ns of the native floor for SHA-256 and 30-50 ns for SHA-512 per update+digest op; the remaining cost is the native library Final+Init (e.g. Final+Init of an empty SHA-512 ctx is ~95 ns, SHA-256 ~40 ns). The other candidate ideas were checked and rejected with evidence: the result byte[] allocation is API-mandated (TLAB bump, not removable), a plain-field needsReinit would save <1 ns with correctness risk for the Cleaner, there is already only one JNI crossing per update(<=256B)+digest(), no FindClass/GetFieldID/GetMethodID on the hot path, the 256B inBuf is not zeroed, API dispatch/bounds checks are the minimum required, and EVP_DigestInit_ex vs _ex2 showed no difference.

## Best Performing State
- Iteration: 4
- Headline OCK: 254158.6, OpenSSL: 291946.7
- Commit Hash: 1b6f7bf160f7acfc1fa785415e3e6a0827b0aed3
- Build UUID: 152e81f4-266c-421c-a1d2-7f3284f738a6
- Note: the improvement over iteration 2 (OCK +0.15%, OpenSSL +0.04%) is within noise.

## Next Steps
- Iteration 5: use a structurally different approach than JNI micro-trims, since iterations 3-4 showed the Java/JNI layer is near the native floor. Options from 'Ideas NOT Yet Tried' in notes/optimization_notes.md: (1) one-shot digest call for tiny inputs (<=256B) that avoids the library Final+Init pair, e.g. EVP_Digest/EVP_Q_digest style on a stack context with a cached EVP_MD* (must avoid the implicit fetch cost of OpenSSL 3.x; no known OCK equivalent); (2) caching of the EVP_MD in the native layer; (3) Panama (Linker) downcalls on JDK 22+ to remove the JNI transition cost (check feasibility: project JDK baseline, OpenJ9 support, native-memory copy cost); (4) any change that reduces native Final+Init cost per op, such as re-using contexts differently (e.g. EVP_MD_CTX_copy_ex from a pre-initialised template ctx instead of Final+Init). Measure each with a local native-floor harness first and only implement if it beats the current Final+Init cost.
