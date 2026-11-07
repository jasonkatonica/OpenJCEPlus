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
One row per individual result (benchmark method x payloadSize x provider). A new column is added after every iteration; Δ columns are vs the iteration 0 baseline and vs the previous iteration. Headline geomean rows are at the bottom.

| Benchmark method | Payload | Provider | Iter 0 baseline | Iter 1 | Iter 2 | Δ iter2 vs baseline | Δ iter2 vs iter1 |
|---|---|---|---|---|---|---|---|
| sha512UpdateDigest | 16 | OCK | 2325553 | 2478580 | 2560354 | +10.1% | +3.3% |
| sha512UpdateDigest | 2048 | OCK | 189334 | 219266 | 218717 | +15.5% | -0.3% |
| sha512UpdateDigest | 32768 | OCK | 14931 | 15030 | 14937 | +0.0% | -0.6% |
| sha512SingleShotDigest | 16 | OCK | 2000677 | 2473122 | 2461462 | +23.0% | -0.5% |
| sha512SingleShotDigest | 2048 | OCK | 217021 | 218848 | 218661 | +0.8% | -0.1% |
| sha512SingleShotDigest | 32768 | OCK | 14987 | 14971 | 15005 | +0.1% | +0.2% |
| md5SingleShotDigest | 16 | OCK | 4378990 | 4909901 | 5476106 | +25.1% | +11.5% |
| md5SingleShotDigest | 2048 | OCK | 316468 | 321401 | 322400 | +1.9% | +0.3% |
| md5SingleShotDigest | 32768 | OCK | 21364 | 21528 | 21530 | +0.8% | +0.0% |
| sha512_224UpdateDigest | 16 | OCK | 2378458 | 2555090 | 2693502 | +13.2% | +5.4% |
| sha512_224UpdateDigest | 2048 | OCK | 210824 | 219635 | 219715 | +4.2% | +0.0% |
| sha512_224UpdateDigest | 32768 | OCK | 12798 | 14992 | 15020 | +17.4% | +0.2% |
| sha512_256UpdateDigest | 16 | OCK | 2196947 | 2572674 | 2694286 | +22.6% | +4.7% |
| sha512_256UpdateDigest | 2048 | OCK | 217790 | 219515 | 219305 | +0.7% | -0.1% |
| sha512_256UpdateDigest | 32768 | OCK | 14986 | 15026 | 15036 | +0.3% | +0.1% |
| md5UpdateDigest | 16 | OCK | 4346669 | 4826728 | 5550417 | +27.7% | +15.0% |
| md5UpdateDigest | 2048 | OCK | 319816 | 321076 | 322481 | +0.8% | +0.4% |
| md5UpdateDigest | 32768 | OCK | 21372 | 21497 | 21497 | +0.6% | +0.0% |
| sha256UpdateDigest | 16 | OCK | 2722196 | 3438296 | 3676474 | +35.1% | +6.9% |
| sha256UpdateDigest | 2048 | OCK | 176460 | 181265 | 181001 | +2.6% | -0.1% |
| sha256UpdateDigest | 32768 | OCK | 10241 | 11967 | 11970 | +16.9% | +0.0% |
| sha1SingleShotDigest | 16 | OCK | 4286429 | 4745368 | 5351120 | +24.8% | +12.8% |
| sha1SingleShotDigest | 2048 | OCK | 361930 | 370026 | 370362 | +2.3% | +0.1% |
| sha1SingleShotDigest | 32768 | OCK | 25879 | 26511 | 26476 | +2.3% | -0.1% |
| sha1UpdateDigest | 16 | OCK | 4306765 | 4867678 | 5345373 | +24.1% | +9.8% |
| sha1UpdateDigest | 2048 | OCK | 352969 | 369443 | 370259 | +4.9% | +0.2% |
| sha1UpdateDigest | 32768 | OCK | 23980 | 26553 | 26547 | +10.7% | -0.0% |
| sha256SingleShotDigest | 16 | OCK | 2979387 | 3448250 | 3648478 | +22.5% | +5.8% |
| sha256SingleShotDigest | 2048 | OCK | 180572 | 181640 | 181507 | +0.5% | -0.1% |
| sha256SingleShotDigest | 32768 | OCK | 11927 | 11983 | 11994 | +0.6% | +0.1% |
| sha512UpdateDigest | 16 | OpenSSL | 2391988 | 2554807 | 2820343 | +17.9% | +10.4% |
| sha512UpdateDigest | 2048 | OpenSSL | 285702 | 298257 | 297299 | +4.1% | -0.3% |
| sha512UpdateDigest | 32768 | OpenSSL | 20662 | 20731 | 20754 | +0.4% | +0.1% |
| sha512SingleShotDigest | 16 | OpenSSL | 2579267 | 2768196 | 2826857 | +9.6% | +2.1% |
| sha512SingleShotDigest | 2048 | OpenSSL | 294728 | 298339 | 297356 | +0.9% | -0.3% |
| sha512SingleShotDigest | 32768 | OpenSSL | 20680 | 20764 | 20770 | +0.4% | +0.0% |
| md5SingleShotDigest | 16 | OpenSSL | 4349339 | 4904280 | 5287648 | +21.6% | +7.8% |
| md5SingleShotDigest | 2048 | OpenSSL | 335274 | 337803 | 338837 | +1.1% | +0.3% |
| md5SingleShotDigest | 32768 | OpenSSL | 22577 | 22638 | 22638 | +0.3% | +0.0% |
| sha512_224UpdateDigest | 16 | OpenSSL | 2594220 | 2767051 | 2852481 | +10.0% | +3.1% |
| sha512_224UpdateDigest | 2048 | OpenSSL | 295509 | 298150 | 297892 | +0.8% | -0.1% |
| sha512_224UpdateDigest | 32768 | OpenSSL | 18283 | 20743 | 20752 | +13.5% | +0.0% |
| sha512_256UpdateDigest | 16 | OpenSSL | 2629171 | 2801300 | 2897696 | +10.2% | +3.4% |
| sha512_256UpdateDigest | 2048 | OpenSSL | 295265 | 296901 | 298706 | +1.2% | +0.6% |
| sha512_256UpdateDigest | 32768 | OpenSSL | 20650 | 20741 | 20747 | +0.5% | +0.0% |
| md5UpdateDigest | 16 | OpenSSL | 4333819 | 4845673 | 5244805 | +21.0% | +8.2% |
| md5UpdateDigest | 2048 | OpenSSL | 333205 | 334457 | 338136 | +1.5% | +1.1% |
| md5UpdateDigest | 32768 | OpenSSL | 22463 | 22630 | 22615 | +0.7% | -0.1% |
| sha256UpdateDigest | 16 | OpenSSL | 2632624 | 3476853 | 3652157 | +38.7% | +5.0% |
| sha256UpdateDigest | 2048 | OpenSSL | 206058 | 208009 | 209875 | +1.9% | +0.9% |
| sha256UpdateDigest | 32768 | OpenSSL | 11578 | 13937 | 13907 | +20.1% | -0.2% |
| sha1SingleShotDigest | 16 | OpenSSL | 4175881 | 4715926 | 5287499 | +26.6% | +12.1% |
| sha1SingleShotDigest | 2048 | OpenSSL | 435973 | 443732 | 443808 | +1.8% | +0.0% |
| sha1SingleShotDigest | 32768 | OpenSSL | 30084 | 30529 | 30492 | +1.4% | -0.1% |
| sha1UpdateDigest | 16 | OpenSSL | 3992695 | 4561486 | 5191979 | +30.0% | +13.8% |
| sha1UpdateDigest | 2048 | OpenSSL | 433131 | 442496 | 443836 | +2.5% | +0.3% |
| sha1UpdateDigest | 32768 | OpenSSL | 28256 | 30572 | 30525 | +8.0% | -0.2% |
| sha256SingleShotDigest | 16 | OpenSSL | 3059962 | 3492679 | 3678623 | +20.2% | +5.3% |
| sha256SingleShotDigest | 2048 | OpenSSL | 208278 | 209229 | 208741 | +0.2% | -0.2% |
| sha256SingleShotDigest | 32768 | OpenSSL | 12685 | 13921 | 13964 | +10.1% | +0.3% |
| **HEADLINE geomean** | all | OCK | 230905.8 | 247801.6 | 253782.2 | +9.91% | +2.41% |
| **HEADLINE geomean** | all | OpenSSL | 268320.8 | 285058.0 | 291841.4 | +8.77% | +2.38% |

Aggregate summary (geomean over the 10 methods, per payload size):
- OCK: 16B +22.6% vs baseline (+7.4% vs iter1); 2048B +3.3% (+0.0%); 32768B +4.8% (-0.0%)
- OpenSSL: 16B +20.3% vs baseline (+7.1% vs iter1); 2048B +1.6% (+0.2%); 32768B +5.3% (-0.0%)

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

## Best Performing State
- Iteration: 2
- Headline OCK: 253782.2, OpenSSL: 291841.4
- Commit Hash: ce6aa00d9b60f1816207a541ef2cd4af2626740a
- Build UUID: 987b76c2-0dc8-4b0c-ab56-f508321b2954

## Next Steps
- Iteration 4: attack the remaining per-call overhead at payload 16B (the only payload where Java/JNI work still pays off). Candidate ideas from notes/optimization_notes.md 'Ideas NOT Yet Tried' and the iteration 3 notes: avoid per-call result byte[] / object allocation where possible, replace shared PrimitiveWrapper.Bool needsReinit bookkeeping with a plain field, reduce JNI crossings or state checks on the update+digest path, reduce MessageDigest API dispatch overhead on the Java side.
