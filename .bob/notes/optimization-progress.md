Iteration 2 - AES/GCM optimization notes

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

Validation status:
- Source compile was attempted with:
  - mvn -q -DskipTests compile
- Build could not complete because Maven enforcer requires:
  - -Dock.library.path
- No benchmark rerun was possible in the current environment for the same reason.

Expected impact:
- Reduced allocation pressure and GC overhead for AES/GCM final/hardware-assisted paths.
- Best-case gains are expected primarily for small/medium payloads and repeated benchmark invocations.
- This iteration does not yet change native GHASH math or CTR internals, so the 15-20% target is not confirmed.

Recommended next iteration:
- Add a true zero-copy fast JNI path for byte[] inputs where safe, or direct ByteBuffer benchmark coverage.
- Investigate native-side fusion opportunities in GCM.c around:
  - AAD/data update sequencing
  - tag buffer handling
  - avoiding duplicate update/final transitions
- Profile whether update-mode GCM paths are paying extra JNI/context overhead versus single-shot doFinal paths.
- If platform support allows, evaluate dedicated GHASH/CTR fused intrinsics beyond current hardware dispatch.