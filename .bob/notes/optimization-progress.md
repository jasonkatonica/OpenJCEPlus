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