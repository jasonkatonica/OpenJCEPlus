# Performance Optimization Progress

## Baseline Measurement
- Benchmark: ibm.jceplus.jmh.MLKEMBenchmark
- Java Version: java26
- Platform: x86_64_linux
- Build UUID: b500a05a-b71d-4132-b874-a5b9f54126d6
- Build URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/java26/18/

### Baseline Scores (ops/s)
Encapsulation:
- ML-KEM-512: 20403.30 ops/s
- ML-KEM-768: 12892.44 ops/s
- ML-KEM-1024: 8914.08 ops/s

Decapsulation:
- ML-KEM-512: 15779.53 ops/s
- ML-KEM-768: 10293.63 ops/s
- ML-KEM-1024: 7323.85 ops/s

Encapsulation + Decapsulation:
- ML-KEM-512: 8914.07 ops/s
- ML-KEM-768: 5725.96 ops/s
- ML-KEM-1024: 4001.66 ops/s

### Target Scores (20% improvement)
Encapsulation:
- ML-KEM-512: 24483.96 ops/s
- ML-KEM-768: 15470.93 ops/s
- ML-KEM-1024: 10696.90 ops/s

Decapsulation:
- ML-KEM-512: 18935.44 ops/s
- ML-KEM-768: 12352.36 ops/s
- ML-KEM-1024: 8788.62 ops/s

Encapsulation + Decapsulation:
- ML-KEM-512: 10696.88 ops/s
- ML-KEM-768: 6871.15 ops/s
- ML-KEM-1024: 4801.99 ops/s

## Optimization Parameters
- Repository: OPENJCEPLUS
- Branch: perf-opt-mlkem-20260603-100144
- Max Iterations: 10
- Regression Threshold: 5%
- Target Improvement: 20%

## Iteration History

### Iteration 0: Baseline
- Status: COMPLETE
- Build UUID: b500a05a-b71d-4132-b874-a5b9f54126d6
- Notes: Initial baseline measurement established

### Iteration 1: Initial Optimizations
- Status: COMPLETE
- Build UUID: 59136f74-d1c4-4d09-8144-326e97297495
- Commit Hash: be0382f74584c34742c9d0ce224af825ae0756e8
- Files Modified: 4 files (196 lines added, 82 removed)

Results (ops/s):
Encapsulation:
- ML-KEM-512: 20414.01 (baseline: 20403.30) = +0.05% improvement
- ML-KEM-768: 12879.37 (baseline: 12892.44) = -0.10% regression
- ML-KEM-1024: 8906.47 (baseline: 8914.08) = -0.09% regression

Decapsulation:
- ML-KEM-512: 15779.97 (baseline: 15779.53) = +0.003% improvement
- ML-KEM-768: 10286.33 (baseline: 10293.63) = -0.07% regression
- ML-KEM-1024: 7320.39 (baseline: 7323.85) = -0.05% regression

Encapsulation + Decapsulation:
- ML-KEM-512: 8876.92 (baseline: 8914.07) = -0.42% regression
- ML-KEM-768: 5707.52 (baseline: 5725.96) = -0.32% regression
- ML-KEM-1024: 4015.11 (baseline: 4001.66) = +0.34% improvement

Analysis:
- All changes are within measurement noise (< 1%)
- No significant performance improvement achieved
- Need more aggressive optimizations
- Target still 20% improvement across all operations

### Iteration 2: Structural Hot-Path Optimizations
- Status: COMPLETE
- Validation Status: Compile passed, ML-KEM tests passed, checkstyle passed
- Files Modified: 2 files (`src/main/java/com/ibm/crypto/plus/provider/base/PQCKey.java`, `src/main/java/com/ibm/crypto/plus/provider/MLKEMImpl.java`)

Optimizations Applied:
1. `PQCKey.java`
   - Replaced repeated `algName.replace('-', '_')` conversions with a cached fast-path mapper for ML-KEM and ML-DSA variants.
   - Made provider/native interface/algorithm fields final to improve JIT optimization opportunities and reduce mutable state in hot paths.
   - Centralized native algorithm-name translation so repeated key generation/import paths avoid transient string allocation.

2. `MLKEMImpl.java`
   - Cached generic ML-KEM mode as a boolean to avoid repeated algorithm identity checks during validation.
   - Streamlined public/private key conversion paths with pattern matching and tighter local handling.
   - Fixed private-key zeroization path to avoid null-sensitive cleanup while preserving secure wiping.
   - Removed redundant temporary handling and kept encapsulation/decapsulation setup focused on validated hot-path work.

Analysis:
- The repository does not expose Java-side NTT, polynomial multiplication, sampling, compression, or Barrett-reduction implementations; ML-KEM arithmetic is delegated to the native OCK library.
- Because of that boundary, iteration 2 focused on the highest-impact accessible structural costs in the Java/provider layer: repeated algorithm normalization, key conversion overhead, and validation-path branching.
- These changes are more aggressive than iteration 1 in the accessible code, but benchmark data was not produced in this environment, so measurable throughput improvement remains unverified.

Validation:
- `mvn -Dock.library.path=/ock clean compile` ✅
- `mvn -Dock.library.path=/ock test -Dtest=*MLKEM*` ✅
- `mvn -Dock.library.path=/ock checkstyle:checkstyle` ✅

## Best Performing State
- Iteration: 0 (Baseline)
- Build UUID: b500a05a-b71d-4132-b874-a5b9f54126d6
- Notes: Iteration 2 completed with validated structural optimizations, but no benchmark results were collected in this environment to prove improvement over baseline.

## Next Steps
- Run `ibm.jceplus.jmh.MLKEMBenchmark` on the target benchmark platform to quantify iteration 2 impact.
- If gains remain below target, the next meaningful step is optimizing the native OCK ML-KEM implementation where polynomial/NTT work actually occurs.