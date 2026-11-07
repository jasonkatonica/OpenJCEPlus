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

## Best Performing State
- Iteration: 0
- Headline OCK: 230905.8, OpenSSL: 268320.6
- Commit Hash: e977e27b4ae20bcdcc45ac7241878e2cb37848df
- Build UUID: 5bdbcec5-355a-4acc-a87a-ed51d54dbf86

## Next Steps
- Iteration 1: inspect the MessageDigest implementation (digest engine classes in the OpenJCEPlus provider and the native/JNI wrappers for OCK and OpenSSL) and the benchmark source in the repo to identify per-call overheads (allocations, redundant native calls, buffer copies, synchronization, state cloning/reset); pick the lowest-risk, highest-impact change.
