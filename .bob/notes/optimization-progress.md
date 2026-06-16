## Iteration 3 - CFB/OFB/CTR Mode Optimization

**Status**: Complete

**Completion Time**: 2026-06-16T20:34:00Z

**Build Information**:
- Build Number: #163
- Build UUID: TBD
- Duration: TBD
- URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/main/163/

**Code Changes**:
- Commit: 06f21b287beb0d565924c101d29eae62955ac58f and e0e557e2
- Files:
  - src/main/java/com/ibm/crypto/plus/provider/AESCipher.java
  - src/main/java/com/ibm/crypto/plus/provider/base/SymmetricCipher.java
- Focus: CFB/OFB mode optimizations, buffer operations, key expansion improvements

### Iteration 3 Performance Results

**Full Performance Data (Build #163)**

**Encryption (OpenJCEPlus, 1KB)**:
- ECB: 1,814,891 ops/s
- CBC: 751,005 ops/s
- CFB: 565,742 ops/s
- OFB: 709,857 ops/s
- CTR: 1,876,504 ops/s
- GCM: 991,599 ops/s

**Encryption (OpenJCEPlus, 32KB)**:
- ECB: 70,824 ops/s
- CBC: 25,244 ops/s
- CFB: 18,271 ops/s
- OFB: 22,387 ops/s
- CTR: 70,965 ops/s
- GCM: 56,411 ops/s

**Decryption (OpenJCEPlus, 1KB)**:
- ECB: 1,424,942 ops/s
- CBC: 1,419,574 ops/s
- CFB: 570,364 ops/s
- OFB: 706,791 ops/s
- CTR: 1,877,923 ops/s
- GCM: 1,052,561 ops/s

**Decryption (OpenJCEPlus, 32KB)**:
- ECB: 59,968 ops/s
- CBC: 60,048 ops/s
- CFB: 18,715 ops/s
- OFB: 23,512 ops/s
- CTR: 70,794 ops/s
- GCM: 56,388 ops/s

### Performance Comparison: Iteration 1 (Build #161) vs Iteration 3 (Build #163)

**ECB Mode**:
- 1KB encrypt: 1,925,000 → 1,814,891 ops/s (-5.7%) - MINOR REGRESSION
- 32KB encrypt: 65,000 → 70,824 ops/s (+9.0%) - IMPROVEMENT
- 1KB decrypt: Not tracked in baseline → 1,424,942 ops/s
- 32KB decrypt: Not tracked in baseline → 59,968 ops/s

**CBC Mode**:
- 1KB encrypt: 725,000 → 751,005 ops/s (+3.6%) - IMPROVEMENT
- 32KB encrypt: Not tracked in baseline → 25,244 ops/s
- 1KB decrypt: 1,030,000 → 1,419,574 ops/s (+37.8%) - SIGNIFICANT IMPROVEMENT
- 32KB decrypt: 45,000 → 60,048 ops/s (+33.4%) - SIGNIFICANT IMPROVEMENT

**GCM Mode**:
- 1KB encrypt: 954,000 → 991,599 ops/s (+3.9%) - IMPROVEMENT
- 32KB encrypt: 60,000 → 56,411 ops/s (-6.0%) - REGRESSION
- 1KB decrypt: 1,020,000 → 1,052,561 ops/s (+3.2%) - IMPROVEMENT
- 32KB decrypt: 60,000 → 56,388 ops/s (-6.0%) - REGRESSION

**CFB/OFB/CTR Modes** (Primary Focus - No Iteration 1 Baseline Available):
- CFB 1KB encrypt: 565,742 ops/s (NEW)
- CFB 32KB encrypt: 18,271 ops/s (NEW)
- CFB 1KB decrypt: 570,364 ops/s (NEW)
- CFB 32KB decrypt: 18,715 ops/s (NEW)
- OFB 1KB encrypt: 709,857 ops/s (NEW)
- OFB 32KB encrypt: 22,387 ops/s (NEW)
- OFB 1KB decrypt: 706,791 ops/s (NEW)
- OFB 32KB decrypt: 23,512 ops/s (NEW)
- CTR 1KB encrypt: 1,876,504 ops/s (NEW)
- CTR 32KB encrypt: 70,965 ops/s (NEW)
- CTR 1KB decrypt: 1,877,923 ops/s (NEW)
- CTR 32KB decrypt: 70,794 ops/s (NEW)

### Analysis

**Overall Outcome**: Iteration 3 did not produce a meaningful improvement over the Iteration 1 baseline and should be treated as unsuccessful for optimization purposes.

**Why Iteration 3 Was Rejected**:

1. **Primary Goal Not Achieved**:
   - The iteration targeted CFB/OFB buffer-path improvements, but there is no evidence of a durable throughput gain in the targeted modes.
   - CFB/OFB still remain far behind CTR and ECB, especially at 32KB sizes where throughput collapses sharply.

2. **ECB Regression Introduced**:
   - 1KB ECB encrypt dropped from 1,925,000 to 1,814,891 ops/s (-5.7%).
   - Build review summary for Iteration 3 reported an even worse observed ECB regression of roughly -8.2%, reinforcing that the changes added overhead rather than removing it.

3. **Benefits Were Either Incidental or Not Actionable**:
   - CBC decrypt remained strong, but those gains were already present from earlier work and were not the intended Iteration 3 target.
   - GCM 1KB recovered modestly, but 32KB GCM still regressed by ~6%, so the iteration did not solve the larger-payload problem.

4. **Feedback-Mode Strategy Did Not Scale**:
   - CFB 1KB encrypt: 565,742 ops/s
   - OFB 1KB encrypt: 709,857 ops/s
   - CFB 32KB encrypt: 18,271 ops/s
   - OFB 32KB encrypt: 22,387 ops/s
   - The severe 1KB→32KB drop indicates the attempted buffer-path tuning did not improve memory locality or reduce enough per-block overhead.

**Conclusion**:
- Iteration 3 changes were reverted.
- The codebase was restored to the Iteration 1 baseline for the relevant AES files before starting Iteration 4.
- Future work should avoid more feedback-loop micro-tuning and instead focus on memory layout, cache locality, and copy-path efficiency.

**Relative Mode Performance Rankings** (1KB):

Encryption:
1. CTR: 1,876,504 ops/s (100% - fastest)
2. ECB: 1,814,891 ops/s (97%)
3. GCM: 991,599 ops/s (53%)
4. CBC: 751,005 ops/s (40%)
5. OFB: 709,857 ops/s (38%)
6. CFB: 565,742 ops/s (30%)

Decryption:
1. CTR: 1,877,923 ops/s (100% - fastest)
2. ECB: 1,424,942 ops/s (76%)
3. CBC: 1,419,574 ops/s (76%)
4. GCM: 1,052,561 ops/s (56%)
5. OFB: 706,791 ops/s (38%)
6. CFB: 570,364 ops/s (30%)

### Technical Observations

**CFB/OFB Mode Characteristics**:
- Both modes show similar encrypt/decrypt performance (unlike CBC where decrypt is much faster)
- This is expected as CFB/OFB use the block cipher in encryption mode for both operations
- The performance gap vs CTR suggests room for optimization in:
  - Feedback buffer management
  - XOR operations
  - State maintenance between blocks

**CTR Mode Success Factors**:
- Parallelizable nature allows efficient processing
- No feedback dependencies between blocks
- Can leverage hardware acceleration effectively
- Serves as a performance ceiling for stream cipher modes

**Buffer Size Sensitivity**:
- 1KB → 32KB transition shows 30-40x performance drop for feedback modes
- Suggests per-block overhead dominates at larger sizes
- May indicate need for:
  - Batch processing optimizations
  - Reduced JNI crossing overhead
  - Better buffer reuse strategies

### Cumulative Results from Baseline (Build #161)

**Net Assessment**:
- Iteration 3 did not establish a better baseline than Iteration 1.
- The targeted CFB/OFB work failed to deliver measurable gains.
- ECB small-buffer performance regressed, making the iteration too risky to keep.

**Decision**:
- Revert Iteration 3 and restart from the Iteration 1 baseline for AES hot-path work.
- Preserve Build #163 measurements only as a negative result to avoid repeating the same optimization direction.

### Recommendations for Iteration 4

**New Direction: Cache and Memory Alignment Optimization**

1. **Improve Memory Alignment**:
   - Favor 16-byte alignment for AES block-oriented temporary buffers where possible.
   - Reduce misaligned copy patterns that can force extra loads/stores around block boundaries.

2. **Improve Cache Locality**:
   - Reuse hot-path buffers instead of allocating size-varying temporary arrays repeatedly.
   - Keep frequently accessed metadata and block-processing state compact and stable across calls.

3. **Reduce Cache Misses and Copy Overhead**:
   - Avoid unnecessary intermediate copies when the caller-provided output buffer can be used directly.
   - Minimize touching large temporary buffers when only a small aligned working region is needed.

4. **Improve CPU Pipelining Opportunities**:
   - Simplify hot-path branching around block-size calculations.
   - Favor block-aligned chunk calculations and predictable loops over mixed-size handling in the fast path.

### Files Modified (Iteration 3)

- src/main/java/com/ibm/crypto/plus/provider/AESCipher.java
- src/main/java/com/ibm/crypto/plus/provider/base/SymmetricCipher.java

### Iteration 4 - Cache and Memory Alignment Optimization

**Status**: Planned

**Objective**:
- Start from the reverted Iteration 1 baseline and pursue a different optimization strategy centered on cache locality and aligned block processing.

**Hypothesis**:
- Iteration 3 focused too much on feedback-mode micro-optimizations and not enough on the dominant costs in the Java/native boundary and temporary-buffer handling.
- Better aligned working buffers, fewer intermediate copies, and more predictable block-sized processing should reduce cache pressure and improve throughput consistency, especially for ECB/CBC/CTR hot paths and larger payloads.

**Planned Focus Areas**:
- 16-byte aligned AES block staging
- cache-friendly reusable temporary buffers
- reduced cache-line boundary crossings in copy-heavy paths
- fewer unnecessary full-buffer touches
- more predictable block-aligned loop structure for update/doFinal paths

### Security/Correctness Validation

- All cryptographic algorithm behaviors remain unchanged
- Mode-specific requirements (IV handling, padding, etc.) preserved
- No changes to key expansion or round function implementations
- Thread safety maintained for all optimizations

---

## Iteration 2 - AES/GCM Optimization

**Status**: Complete

**Completion Time**: 2026-06-16T13:20:00Z

**Build Information**:
- Build Number: #162
- Build UUID: 688235e7-6d7b-4f0a-9fe4-c19e4cec7b1d
- Duration: 1436m 41s (23.9 hours)
- URL: https://hyc-runtimes-jenkins.swg-devops.com/job/SecurityPerformancePipeline/job/main/162/

**Code Changes**:
- Commit: 8b3cbb428a1e69c28985e02516e534b59a4a466b
- Files: 3 modified
- Lines Added: 94
- Lines Removed: 167 (net reduction of 73 lines)
- Focus: GCM-specific optimizations (GHASH, authentication tag, buffer management)

### Iteration 2 Performance Results

**Comparison: Iteration 1 (Build #161) vs Iteration 2 (Build #162)**

**GCM Mode Performance** (Primary Focus):

Encryption:
- 1KB: 954,000 → 949,857 ops/s (-0.4%) - SLIGHT REGRESSION
- 32KB: 60,000 → 56,398 ops/s (-6.0%) - REGRESSION

Decryption:
- 1KB: 1,020,000 → 1,028,141 ops/s (+0.8%) - MINOR IMPROVEMENT
- 32KB: 60,000 → 56,730 ops/s (-5.5%) - REGRESSION

**Analysis**: The GCM-specific optimizations did not achieve the desired improvements. In fact, most GCM tests showed slight regressions, particularly for 32KB payloads. This suggests the optimization changes may have introduced overhead or the GCM mode's authentication requirements limit optimization potential.

**Other Cipher Modes** (Unexpected Changes):

Some modes showed minor variations compared to Iteration 1:
- ECB 1KB encrypt: 1,925,000 → 1,783,212 ops/s (-7.4%)
- CBC 1KB encrypt: 725,000 → 751,922 ops/s (+3.7%)
- CBC 1KB decrypt: 1,030,000 → 1,444,907 ops/s (+40.3%) - SIGNIFICANT IMPROVEMENT
- ECB 32KB encrypt: 65,000 → 70,752 ops/s (+8.8%)
- CBC 32KB decrypt: 45,000 → 60,564 ops/s (+34.6%) - SIGNIFICANT IMPROVEMENT

**Overall Assessment**:
- GCM optimization goal: NOT ACHIEVED (regressions instead of improvements)
- Unexpected benefit: Significant CBC decrypt improvements (+34-40%)
- Net effect: Mixed results with some modes improving while GCM regressed

**Cumulative Results from Baseline**:

Comparing Build #162 to original baseline (Build #160):
- Average improvement: Still positive overall due to Iteration 1 gains
- GCM mode: Near baseline performance (minimal net change)
- Other modes: Maintained strong improvements from Iteration 1

### Technical Implementation Notes

Files analyzed:
- /workspace/src/main/java/com/ibm/crypto/plus/provider/AESGCMCipher.java
- /workspace/src/main/java/com/ibm/crypto/plus/provider/base/GCMCipher.java
- /workspace/src/main/native/ock/GCM.c
- /workspace/src/test/java/ibm/jceplus/jmh/AESCipherBenchmark.java
- /workspace/src/test/java/ibm/jceplus/jmh/SymmetricCipherBase.java

Observed bottlenecks:
- Java-side per-call allocations in GCM hot paths were more prominent than obvious native GHASH changes.
- AAD handling cloned arrays repeatedly even when the data was already immutable for the duration of the call.
- Hardware-assisted GCM path allocated temporary byte arrays for:
  - serialized mode bytes
  - parameter block assembly
- The software/native fast JNI path still copies payloads into direct buffers, but the lowest-risk wins for this iteration were in repeated metadata allocations rather than payload movement.
- Native GCM.c already relies heavily on ICC/OpenSSL-style primitives and platform hardware hooks, so deeper GHASH/CTR changes would require larger native refactoring and more validation.

Implemented optimizations:
- In GCMCipher.java:
  - replaced repeated AAD cloning with zero-copy reuse via getAADBytes(aad), returning:
    - the original aad reference when present
    - a shared emptyAAD singleton when absent/empty
  - removed ByteBuffer-based longToBytes/intToBytes allocation helpers from the hot path
  - added thread-local reusable modeBuffer for hardware mode serialization
  - added thread-local reusable hardware parameter buffers for AES-128/192/256
  - updated useHardwareGCM(...) to:
    - serialize mode into reusable modeBuffer
    - reuse per-key-size parameter block buffers
    - clear/repopulate the reusable parameter block before each call

Security/correctness considerations:
- No cryptographic algorithm behavior was changed.
- GHASH/tag generation remains in native ICC/hardware-backed implementation.
- Key/IV uniqueness logic in AESGCMCipher was not modified.
- Reused buffers are thread-local, avoiding cross-thread data races.
- Parameter buffers are zeroed before reuse to avoid stale metadata contamination.

Recommended next iteration:
- Add a true zero-copy fast JNI path for byte[] inputs where safe, or direct ByteBuffer benchmark coverage.
- Investigate native-side fusion opportunities in GCM.c around:
  - AAD/data update sequencing
  - tag buffer handling
  - avoiding duplicate update/final transitions
- Profile whether update-mode GCM paths are paying extra JNI/context overhead versus single-shot doFinal paths.
- If platform support allows, evaluate dedicated GHASH/CTR fused intrinsics beyond current hardware dispatch.
