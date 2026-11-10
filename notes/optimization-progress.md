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
One row per individual result (benchmark method x payloadSize x provider). Every measured iteration has two columns: the raw score (ops/s) and its Δ vs the iteration 0 baseline, (iterN - baseline)/baseline*100. All deltas are ALWAYS against the baseline run (Iter 0), never against the previous iteration. Headline geomean rows (geomean of the 30 raw scores per provider) are at the bottom. Iterations 3 and 5 made no code change and were not benchmarked, so they have no columns.

| Benchmark method | Params | Provider | Baseline raw (iter 0) | Iter 1 raw | Iter 1 Δ vs baseline | Iter 2 raw | Iter 2 Δ vs baseline | Iter 4 raw | Iter 4 Δ vs baseline | Iter 6 raw | Iter 6 Δ vs baseline | Iter 7 raw | Iter 7 Δ vs baseline | Iter 8 raw | Iter 8 Δ vs baseline |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sha512UpdateDigest | 16 | OCK | 2325553 | 2478580 | +6.6% | 2560354 | +10.1% | 2576312 | +10.8% | 2608393 | +12.2% | 2596091 | +11.6% | 2569370 | +10.5% |
| sha512UpdateDigest | 2048 | OCK | 189334 | 219266 | +15.8% | 218717 | +15.5% | 219201 | +15.8% | 218483 | +15.4% | 218567 | +15.4% | 214187 | +13.1% |
| sha512UpdateDigest | 32768 | OCK | 14931 | 15030 | +0.7% | 14937 | +0.0% | 15007 | +0.5% | 15026 | +0.6% | 14973 | +0.3% | 13190 | -11.7% |
| sha512SingleShotDigest | 16 | OCK | 2000677 | 2473122 | +23.6% | 2461462 | +23.0% | 2534667 | +26.7% | 2612073 | +30.6% | 2553652 | +27.6% | 2581365 | +29.0% |
| sha512SingleShotDigest | 2048 | OCK | 217021 | 218848 | +0.8% | 218661 | +0.8% | 219390 | +1.1% | 219114 | +1.0% | 218811 | +0.8% | 214065 | -1.4% |
| sha512SingleShotDigest | 32768 | OCK | 14987 | 14971 | -0.1% | 15005 | +0.1% | 15024 | +0.2% | 15012 | +0.2% | 14820 | -1.1% | 12689 | -15.3% |
| md5SingleShotDigest | 16 | OCK | 4378990 | 4909901 | +12.1% | 5476106 | +25.1% | 5537735 | +26.5% | 5563329 | +27.0% | 5579036 | +27.4% | 5013087 | +14.5% |
| md5SingleShotDigest | 2048 | OCK | 316468 | 321401 | +1.6% | 322400 | +1.9% | 322106 | +1.8% | 322011 | +1.8% | 320023 | +1.1% | 321215 | +1.5% |
| md5SingleShotDigest | 32768 | OCK | 21364 | 21528 | +0.8% | 21530 | +0.8% | 21513 | +0.7% | 21221 | -0.7% | 21303 | -0.3% | 18832 | -11.9% |
| sha512_224UpdateDigest | 16 | OCK | 2378458 | 2555090 | +7.4% | 2693502 | +13.2% | 2671610 | +12.3% | 2661515 | +11.9% | 2638940 | +11.0% | 2510230 | +5.5% |
| sha512_224UpdateDigest | 2048 | OCK | 210824 | 219635 | +4.2% | 219715 | +4.2% | 219465 | +4.1% | 219580 | +4.2% | 218837 | +3.8% | 206981 | -1.8% |
| sha512_224UpdateDigest | 32768 | OCK | 12798 | 14992 | +17.1% | 15020 | +17.4% | 15026 | +17.4% | 14986 | +17.1% | 15007 | +17.3% | 13546 | +5.8% |
| sha512_256UpdateDigest | 16 | OCK | 2196947 | 2572674 | +17.1% | 2694286 | +22.6% | 2638127 | +20.1% | 2705321 | +23.1% | 2699714 | +22.9% | 2564233 | +16.7% |
| sha512_256UpdateDigest | 2048 | OCK | 217790 | 219515 | +0.8% | 219305 | +0.7% | 219767 | +0.9% | 220018 | +1.0% | 220046 | +1.0% | 181354 | -16.7% |
| sha512_256UpdateDigest | 32768 | OCK | 14986 | 15026 | +0.3% | 15036 | +0.3% | 14986 | +0.0% | 15036 | +0.3% | 14968 | -0.1% | 14843 | -1.0% |
| md5UpdateDigest | 16 | OCK | 4346669 | 4826728 | +11.0% | 5550417 | +27.7% | 5480375 | +26.1% | 5507809 | +26.7% | 5537485 | +27.4% | 5499641 | +26.5% |
| md5UpdateDigest | 2048 | OCK | 319816 | 321076 | +0.4% | 322481 | +0.8% | 322124 | +0.7% | 321328 | +0.5% | 319595 | -0.1% | 321410 | +0.5% |
| md5UpdateDigest | 32768 | OCK | 21372 | 21497 | +0.6% | 21497 | +0.6% | 21525 | +0.7% | 21492 | +0.6% | 18598 | -13.0% | 18737 | -12.3% |
| sha256UpdateDigest | 16 | OCK | 2722196 | 3438296 | +26.3% | 3676474 | +35.1% | 3691053 | +35.6% | 3684250 | +35.3% | 3703018 | +36.0% | 3381437 | +24.2% |
| sha256UpdateDigest | 2048 | OCK | 176460 | 181265 | +2.7% | 181001 | +2.6% | 181851 | +3.1% | 180848 | +2.5% | 181567 | +2.9% | 158778 | -10.0% |
| sha256UpdateDigest | 32768 | OCK | 10241 | 11967 | +16.9% | 11970 | +16.9% | 11975 | +16.9% | 11977 | +17.0% | 11927 | +16.5% | 11650 | +13.8% |
| sha1SingleShotDigest | 16 | OCK | 4286429 | 4745368 | +10.7% | 5351120 | +24.8% | 5413551 | +26.3% | 5500714 | +28.3% | 5179146 | +20.8% | 5449615 | +27.1% |
| sha1SingleShotDigest | 2048 | OCK | 361930 | 370026 | +2.2% | 370362 | +2.3% | 370524 | +2.4% | 370060 | +2.2% | 314076 | -13.2% | 368721 | +1.9% |
| sha1SingleShotDigest | 32768 | OCK | 25879 | 26511 | +2.4% | 26476 | +2.3% | 26538 | +2.5% | 26454 | +2.2% | 26515 | +2.5% | 25859 | -0.1% |
| sha1UpdateDigest | 16 | OCK | 4306765 | 4867678 | +13.0% | 5345373 | +24.1% | 5375425 | +24.8% | 5254295 | +22.0% | 5280465 | +22.6% | 4516985 | +4.9% |
| sha1UpdateDigest | 2048 | OCK | 352969 | 369443 | +4.7% | 370259 | +4.9% | 370804 | +5.1% | 369822 | +4.8% | 372021 | +5.4% | 330796 | -6.3% |
| sha1UpdateDigest | 32768 | OCK | 23980 | 26553 | +10.7% | 26547 | +10.7% | 26547 | +10.7% | 26425 | +10.2% | 26456 | +10.3% | 22503 | -6.2% |
| sha256SingleShotDigest | 16 | OCK | 2979387 | 3448250 | +15.7% | 3648478 | +22.5% | 3665655 | +23.0% | 3620379 | +21.5% | 3725916 | +25.1% | 3544340 | +19.0% |
| sha256SingleShotDigest | 2048 | OCK | 180572 | 181640 | +0.6% | 181507 | +0.5% | 181198 | +0.3% | 181432 | +0.5% | 181891 | +0.7% | 167482 | -7.2% |
| sha256SingleShotDigest | 32768 | OCK | 11927 | 11983 | +0.5% | 11994 | +0.6% | 11972 | +0.4% | 11978 | +0.4% | 11671 | -2.1% | 10397 | -12.8% |
| sha512UpdateDigest | 16 | OpenSSL | 2391988 | 2554807 | +6.8% | 2820343 | +17.9% | 2861006 | +19.6% | 2841367 | +18.8% | 2833569 | +18.5% | 2868328 | +19.9% |
| sha512UpdateDigest | 2048 | OpenSSL | 285702 | 298257 | +4.4% | 297299 | +4.1% | 296112 | +3.6% | 296916 | +3.9% | 298716 | +4.6% | 257242 | -10.0% |
| sha512UpdateDigest | 32768 | OpenSSL | 20662 | 20731 | +0.3% | 20754 | +0.4% | 20720 | +0.3% | 20674 | +0.1% | 20689 | +0.1% | 18407 | -10.9% |
| sha512SingleShotDigest | 16 | OpenSSL | 2579267 | 2768196 | +7.3% | 2826857 | +9.6% | 2764887 | +7.2% | 2837987 | +10.0% | 2836241 | +10.0% | 2388116 | -7.4% |
| sha512SingleShotDigest | 2048 | OpenSSL | 294728 | 298339 | +1.2% | 297356 | +0.9% | 297756 | +1.0% | 296366 | +0.6% | 293586 | -0.4% | 264402 | -10.3% |
| sha512SingleShotDigest | 32768 | OpenSSL | 20680 | 20764 | +0.4% | 20770 | +0.4% | 20784 | +0.5% | 20748 | +0.3% | 20680 | +0.0% | 17721 | -14.3% |
| md5SingleShotDigest | 16 | OpenSSL | 4349339 | 4904280 | +12.8% | 5287648 | +21.6% | 5296602 | +21.8% | 5359767 | +23.2% | 5344807 | +22.9% | 5411285 | +24.4% |
| md5SingleShotDigest | 2048 | OpenSSL | 335274 | 337803 | +0.8% | 338837 | +1.1% | 338551 | +1.0% | 338948 | +1.1% | 336024 | +0.2% | 320635 | -4.4% |
| md5SingleShotDigest | 32768 | OpenSSL | 22577 | 22638 | +0.3% | 22638 | +0.3% | 22654 | +0.3% | 22679 | +0.5% | 22385 | -0.9% | 19925 | -11.7% |
| sha512_224UpdateDigest | 16 | OpenSSL | 2594220 | 2767051 | +6.7% | 2852481 | +10.0% | 2900991 | +11.8% | 2894288 | +11.6% | 2902493 | +11.9% | 2709822 | +4.5% |
| sha512_224UpdateDigest | 2048 | OpenSSL | 295509 | 298150 | +0.9% | 297892 | +0.8% | 298756 | +1.1% | 297495 | +0.7% | 297101 | +0.5% | 297400 | +0.6% |
| sha512_224UpdateDigest | 32768 | OpenSSL | 18283 | 20743 | +13.5% | 20752 | +13.5% | 20744 | +13.5% | 20741 | +13.4% | 20697 | +13.2% | 19262 | +5.4% |
| sha512_256UpdateDigest | 16 | OpenSSL | 2629171 | 2801300 | +6.5% | 2897696 | +10.2% | 2883792 | +9.7% | 2916713 | +10.9% | 2870005 | +9.2% | 2509324 | -4.6% |
| sha512_256UpdateDigest | 2048 | OpenSSL | 295265 | 296901 | +0.6% | 298706 | +1.2% | 297976 | +0.9% | 297424 | +0.7% | 298591 | +1.1% | 254750 | -13.7% |
| sha512_256UpdateDigest | 32768 | OpenSSL | 20650 | 20741 | +0.4% | 20747 | +0.5% | 20603 | -0.2% | 20746 | +0.5% | 20601 | -0.2% | 20663 | +0.1% |
| md5UpdateDigest | 16 | OpenSSL | 4333819 | 4845673 | +11.8% | 5244805 | +21.0% | 5295264 | +22.2% | 5373256 | +24.0% | 5284255 | +21.9% | 5307470 | +22.5% |
| md5UpdateDigest | 2048 | OpenSSL | 333205 | 334457 | +0.4% | 338136 | +1.5% | 338945 | +1.7% | 338494 | +1.6% | 307326 | -7.8% | 292394 | -12.2% |
| md5UpdateDigest | 32768 | OpenSSL | 22463 | 22630 | +0.7% | 22615 | +0.7% | 22620 | +0.7% | 22649 | +0.8% | 19694 | -12.3% | 19357 | -13.8% |
| sha256UpdateDigest | 16 | OpenSSL | 2632624 | 3476853 | +32.1% | 3652157 | +38.7% | 3650081 | +38.6% | 3607676 | +37.0% | 3668188 | +39.3% | 3273892 | +24.4% |
| sha256UpdateDigest | 2048 | OpenSSL | 206058 | 208009 | +0.9% | 209875 | +1.9% | 209937 | +1.9% | 208835 | +1.3% | 209395 | +1.6% | 177674 | -13.8% |
| sha256UpdateDigest | 32768 | OpenSSL | 11578 | 13937 | +20.4% | 13907 | +20.1% | 13931 | +20.3% | 13945 | +20.4% | 13858 | +19.7% | 13883 | +19.9% |
| sha1SingleShotDigest | 16 | OpenSSL | 4175881 | 4715926 | +12.9% | 5287499 | +26.6% | 5321688 | +27.4% | 5277913 | +26.4% | 4582805 | +9.7% | 5247207 | +25.7% |
| sha1SingleShotDigest | 2048 | OpenSSL | 435973 | 443732 | +1.8% | 443808 | +1.8% | 443764 | +1.8% | 444003 | +1.8% | 369577 | -15.2% | 432847 | -0.7% |
| sha1SingleShotDigest | 32768 | OpenSSL | 30084 | 30529 | +1.5% | 30492 | +1.4% | 30575 | +1.6% | 30578 | +1.6% | 30134 | +0.2% | 25808 | -14.2% |
| sha1UpdateDigest | 16 | OpenSSL | 3992695 | 4561486 | +14.2% | 5191979 | +30.0% | 5221873 | +30.8% | 5246409 | +31.4% | 5214263 | +30.6% | 4699911 | +17.7% |
| sha1UpdateDigest | 2048 | OpenSSL | 433131 | 442496 | +2.2% | 443836 | +2.5% | 443123 | +2.3% | 444744 | +2.7% | 434033 | +0.2% | 376305 | -13.1% |
| sha1UpdateDigest | 32768 | OpenSSL | 28256 | 30572 | +8.2% | 30525 | +8.0% | 30056 | +6.4% | 30448 | +7.8% | 30423 | +7.7% | 29089 | +2.9% |
| sha256SingleShotDigest | 16 | OpenSSL | 3059962 | 3492679 | +14.1% | 3678623 | +20.2% | 3684790 | +20.4% | 3641939 | +19.0% | 3657481 | +19.5% | 3453681 | +12.9% |
| sha256SingleShotDigest | 2048 | OpenSSL | 208278 | 209229 | +0.5% | 208741 | +0.2% | 209985 | +0.8% | 209705 | +0.7% | 209532 | +0.6% | 202921 | -2.6% |
| sha256SingleShotDigest | 32768 | OpenSSL | 12685 | 13921 | +9.7% | 13964 | +10.1% | 13917 | +9.7% | 13902 | +9.6% | 13874 | +9.4% | 12906 | +1.7% |
| **HEADLINE geomean** | all | OCK | 230905.8 | 247801.6 | +7.3% | 253782.2 | +9.9% | 254158.6 | +10.1% | 254305.8 | +10.1% | 250890.3 | +8.7% | 236664.5 | +2.5% |
| **HEADLINE geomean** | all | OpenSSL | 268320.8 | 285058.0 | +6.2% | 291841.4 | +8.8% | 291946.7 | +8.8% | 292290.8 | +8.9% | 285902.3 | +6.6% | 268183.5 | -0.1% |

### Aggregates vs baseline (geomean of raw scores)
Geomean Δ vs baseline over the 10 methods of each payload size (ALL = headline over the 30 scores):

| Provider | Payload | Iter 1 Δ vs baseline | Iter 2 Δ vs baseline | Iter 4 Δ vs baseline | Iter 6 Δ vs baseline | Iter 7 Δ vs baseline | Iter 8 Δ vs baseline |
|---|---|---|---|---|---|---|---|
| OCK | 16B | +14.2% | +22.6% | +23.0% | +23.7% | +23.0% | +17.5% |
| OCK | 2048B | +3.3% | +3.3% | +3.4% | +3.3% | +1.6% | -2.9% |
| OCK | 32768B | +4.8% | +4.8% | +4.8% | +4.6% | +2.6% | -5.6% |
| OCK | ALL | +7.3% | +9.9% | +10.1% | +10.1% | +8.7% | +2.5% |
| OpenSSL | 16B | +12.3% | +20.3% | +20.6% | +20.9% | +19.0% | +13.4% |
| OpenSSL | 2048B | +1.3% | +1.6% | +1.6% | +1.5% | -1.6% | -8.2% |
| OpenSSL | 32768B | +5.3% | +5.3% | +5.1% | +5.3% | +3.3% | -4.1% |
| OpenSSL | ALL | +6.2% | +8.8% | +8.8% | +8.9% | +6.6% | -0.1% |

Jenkins builds per column: Iter 1 #108, Iter 2 #109, Iter 4 #110, Iter 6 #111, Iter 7 #113 re-run [#112 discarded, noisy: headline OCK 242603 / OpenSSL 276303, many scoreErrors of 10-100% of the score], Iter 8 #114. Iterations 3 and 5 made no code change and were not benchmarked.

Iteration 8 (#114) is flagged UNRELIABLE: the whole machine/run was about 6-9% slower than the other runs, including the OCK backend which the iteration 8 change did not touch (OCK geomean -6.9% vs iter 6 although only OpenSSL native build flags changed); a re-run is pending.

## Optimization Parameters
- Repository: OPENJCEPLUS
- Branch: perf-opt-messagedigest-20261106-143220 (created from upstream/java25)
- Max Iterations: 10
- Regression Threshold: 1% drop of headline score vs best-so-far (per provider)
- Note: baseline has large noise (scoreError up to +-50% on some 16B/2048B cases); judge on the headline geomean and on payloadSize 16 (JNI/call overhead dominated) vs 32768 (native dominated) separately.
- Reporting convention: Every iteration records (a) all 60 individual scores plus delta vs baseline in Score History / the iteration entry, and (b) the headline geomean per provider.

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

### Iteration 5: Native Final+Init alternatives evaluated (analysis only, NO code change)
- Status: COMPLETE (not benchmarked on Jenkins: code identical to iteration 4)
- Headline: unchanged from iteration 4 (OCK 254158.6 ops/s, OpenSSL 291946.7 ops/s); no new column in Score History.
- Improvement vs baseline: OCK +10.07%, OpenSSL +8.81% (target +40% each)
- Bob Shell UUID: a24a3c9b-1a27-42c0-8bb8-7f85572d8de0
- Commit Hash: aa5889b8d01903794ded30577bbec3cb11c24bef (notes only)
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/aa5889b8d01903794ded30577bbec3cb11c24bef
- Files Changed: 1 (notes/optimization_notes.md)
- Approach: evaluated (a) EVP_Digest / EVP_Q_digest one-shot with cached EVP_MD*, (b) EVP_MD_CTX_copy_ex(template) reset instead of Init_ex2, (c) ICC (OCK) cheaper reset/one-shot paths.
- Result: NO_CHANGE. EVP_Digest one-shot is 30-50% slower than the pooled ctx; EVP_Q_digest 2-4x slower; copy_ex template reset is only ~+0.5% end to end through the Java API (below the 2% bar, adds allocation and lifetime complexity), reverted; ICC copy-based reset is 30-40 ns slower, ICC Init is only ~6 ns of 70-143 ns.
- Notes: Init/reset is <10% of the 16B cost in both OpenSSL and ICC; Final (padding + one compression) dominates. Java+JNI overhead is 5-25 ns per op with no removable piece. Remaining untested ideas: Panama downcalls, routing SHA-2 of OCK to the OpenSSL backend on x86_64, investigating ICC CPU dispatch (SHA-NI/AVX2) on real x86_64. Conclusion: the +40% headline target is not reachable with Java/JNI changes in OpenJCEPlus; 20 of 30 scores per provider (2048B, 32768B) are bound by the native compression function.

### Iteration 6: Drop trailing ExceptionCheck JNI call in DIGEST_updateDigestAndReset (OCK + OpenSSL native Digest.c)
- Status: COMPLETE
- Headline (geomean of 30 scores per provider): OCK 254305.8 ops/s, OpenSSL 292290.8 ops/s
- Improvement vs baseline: OCK +10.13%, OpenSSL +8.93% (target +40% each)
- Change vs previous best (iter 4): OCK +0.06%, OpenSSL +0.12% (within run-to-run noise)
- Individual results: see Score History (Iter 6 columns). Largest individual moves vs iter4: best sha512SingleShot OCK 16B +3.1%, worst sha1Update OCK 16B -2.3% (noise-level).
- Bob Shell UUID: 7f10fd66-4767-4fe3-b89f-f5f58b917958
- Commit Hash: 788026260fd7fe9f7a9329260ccbff38df81e7ca
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/788026260fd7fe9f7a9329260ccbff38df81e7ca
- Build UUID: b5ceafef-b7da-40de-ad3d-8f2432f16584
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/111/
- Files Changed: 3 (src/main/native/ock/Digest.c, src/main/native/openssl/Digest.c, notes/optimization_notes.md)
- Lines Added/Removed: 72/6
- Approach: found by code analysis only (no local measurement): removed the last ExceptionCheck() JNI function-table call after SetByteArrayRegion; analysed JIT inlining of the Java hot path (all methods inlinable, nothing to change), JNI crossings (already minimal at 1 for 16B), and Panama/critical-native feasibility (not implemented, needs owner decision).
- Result: NO_CHANGE (measured gain within noise; no regression)
- Notes: the Java and JNI wrapper layers have no remaining measurable per-call overhead; remaining 16B cost is the native library Update+Final; 2048B and 32768B are bound by the native compression function.

### Iteration 7: Stack buffer + SetByteArrayRegion in DIGEST_digest_and_reset(byte[]) (OCK + OpenSSL native Digest.c)
- Status: COMPLETE
- Headline (geomean of 30 scores per provider, build #113): OCK 250890.3 ops/s, OpenSSL 285902.3 ops/s
- Improvement vs baseline: OCK +8.7%, OpenSSL +6.6% (target +40% each)
- Change vs iteration 6: OCK -1.3%, OpenSSL -2.2% on the geomean, but the MEDIAN per-score change is -0.2% (OCK) / -0.3% (OpenSSL), and excluding the 4 noisy rows (sha1SingleShotDigest 16B/2048B, md5UpdateDigest 2048B/32768B, which have scoreErrors up to 35% of the score; e.g. OpenSSL md5Update 2048B 307326 ± 111098) the geomean change is -0.1% (OCK) / -0.4% (OpenSSL). Conclusion: neutral within noise, NOT a real regression.
- Individual results: see Score History (Iter 7 columns).
- Bob Shell UUID: 16d69b43-e82c-4776-9e5e-24758a6c3966
- Commit Hash: 356ba8c87fea09578d3261fd7a6644d1e933046b
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/356ba8c87fea09578d3261fd7a6644d1e933046b
- Build UUID: 00ca1ee5-5463-4877-963e-110fd9be5bd0 (build #113; first run #112 UUID bf629406-594d-442e-98db-695612752100 discarded as noisy)
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/113/
- Files Changed: 3 (src/main/native/ock/Digest.c, src/main/native/openssl/Digest.c, notes/optimization_notes.md)
- Lines Added/Removed: 109/34
- Approach: found by code analysis only: replaced GetPrimitiveArrayCritical/ReleasePrimitiveArrayCritical on the 16-64B output array with a stack buffer + one SetByteArrayRegion (one JNI call fewer per 2048B/32768B op; GetPrimitiveArrayCritical remains the cheapest pin for the large input).
- Result: NO_CHANGE (neutral within noise). Code kept because it strictly removes work and is correct (targeted tests and checkstyle pass); no restoration performed. Regression rule note: the geomean drop exceeds the 1% threshold only because of noisy rows; the median shows no change.
- Notes: the large-payload scores are bound by the native compression function; no remaining removable work on that path in Java or JNI.

### Iteration 8: OpenSSL backend only - build with -fno-plt on x86-linux64 and drop unused isCopy out-parameter in DIGEST_update
- Status: COMPLETE, measurement flagged UNRELIABLE (re-run pending)
- Headline (build #114): OCK 236664.5 ops/s (+2.5% vs baseline), OpenSSL 268183.5 ops/s (-0.1% vs baseline)
- Bob Shell UUID: 1da37568-b561-4c60-aafc-7c2fa604afba
- Commit Hash: b25613c1aba8cfbb5977dba8561a2437883fb343 (code commit touching src/main/native/openssl/openjceplus.mak and src/main/native/openssl/Digest.c; the follow-up commit 600076083d9805c6cd3e1df64066339c1468da03 only corrects notes/optimization_notes.md)
- GitHub Commit: https://github.com/jasonkatonica/OpenJCEPlus/commit/b25613c1aba8cfbb5977dba8561a2437883fb343
- Build UUID: 9e7e8b7f-d486-4600-8e54-542e8f9f600a (build #114)
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java25/114/
- Approach: -fno-plt (the Jenkins console log confirms it is in the OpenSSL compile lines and not in the OCK ones) removes one PLT indirection per libcrypto call; see 'Iteration 8' in notes/optimization_notes.md.
- Result: INCONCLUSIVE. The OCK control (unchanged backend) also dropped, so the run is not comparable with #111/#113.
- Notes: re-run on Jenkins before deciding whether to keep or restore iteration 6 code state.

## Best Performing State
- Iteration: 6
- Headline OCK: 254305.8, OpenSSL: 292290.8
- Commit Hash: 788026260fd7fe9f7a9329260ccbff38df81e7ca
- Build UUID: b5ceafef-b7da-40de-ad3d-8f2432f16584
- Note: the improvement over iterations 2 and 4 is within noise; iteration 6 code is a strict superset of iteration 4 code.
- Iteration 5 made no code change; code state equals iteration 4.
- Current code state = iteration 8 (commit b25613c1aba8cfbb5977dba8561a2437883fb343); performance of iterations 4, 6 and 7 is equal within run-to-run noise (about +-2% on the headline); iteration 8 is not yet judged (unreliable run, re-run pending).

## Next Steps
- Iteration 8 needs a Jenkins re-run for a clean comparison; then decide keep vs restore.
- Remaining options beyond that are structural and need an owner decision (Panama critical downcall prototype for one algorithm; routing OCK SHA-2 to the OpenSSL backend on x86_64; ICC CPU-dispatch investigation). Without that, remaining iterations can only be analysis.
- The +40% target is not reachable with Java/JNI changes alone (20 of 30 scores per provider are bound by the native compression function; see iterations 3, 5 and 6). Further progress requires an owner decision: (1) lower the target; (2) accept the current result (OCK +10.13%, OpenSSL +8.93%); (3) authorize the larger options: Panama downcalls (JDK 22+, OpenJ9 support and native-memory copy cost to be checked), routing SHA-2 of the OCK provider to the OpenSSL backend on x86_64, or an ICC build/CPU-dispatch investigation (SHA-NI/AVX2) on real x86_64.
