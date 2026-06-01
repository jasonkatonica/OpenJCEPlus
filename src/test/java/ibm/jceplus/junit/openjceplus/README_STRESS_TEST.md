# PQC Key Interop Stress Test

## Overview

`TestPQCKeyInteropStressLoop.java` is a standalone stress test designed to reproduce intermittent PQC (Post-Quantum Cryptography) key interoperability failures between OpenJCEPlus and SunJCE providers.

## Purpose

This test continuously loops to catch race conditions or intermittent issues in:
- KEM (Key Encapsulation Mechanism) operations
- ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) with various parameter sets
- ML-DSA (Module-Lattice-Based Digital Signature Algorithm) signature verification

## Failures Being Reproduced

Based on the Jenkins test failures, this test targets:
- `testPQCKeyGenKEMAutoKeyConvertion` - Secrets do NOT match
- `testKEMInteropKeyPlusAll` - Secrets do NOT match for ML-KEM variants
- `testMLKEMInteropEmptyParamsWithNamedParameterSpec` - Encapsulated and decapsulated keys do not match
- `testPQCKeyGenKEM_Interop` - Key encoding mismatches
- `testPQCKeyGenKEM_PlusToInteropRAW` - Key conversion failures
- `testSignInteropKeysPlusSignVerify` - Signature verification failures

## Requirements

- Java 21 or later (KEM API was introduced in Java 21)
- OpenJCEPlus provider compiled and available
- SunJCE provider (included in JDK)

## Running the Test

### Option 1: Using Maven

```bash
# Compile the test
mvn test-compile

# Run the stress test (will loop indefinitely)
mvn test -Dtest=TestPQCKeyInteropStressLoop
```

### Option 2: Direct Java Execution

```bash
# Compile first
mvn test-compile

# Run directly
java -cp target/test-classes:target/classes \
  ibm.jceplus.junit.openjceplus.TestPQCKeyInteropStressLoop
```

### Option 3: With Custom Classpath

```bash
java -cp target/test-classes:target/classes:path/to/openjceplus.jar \
  ibm.jceplus.junit.openjceplus.TestPQCKeyInteropStressLoop
```

## Test Output

The test will display:
- Current iteration number
- Total failures detected
- Failure rate percentage
- Detailed error information when failures occur
- Success confirmation for each iteration

Example output:
```
================================================================================
Iteration #1234 - Failures so far: 5
================================================================================

[Test] KEM Auto Key Conversion (SunJCE -> OpenJCEPlus)
  ✓ Secrets match

[Test] KEM Interop (OpenJCEPlus keys -> SunJCE operations)
  ✓ Key conversion successful

...

✓ Iteration #1234 PASSED
```

When a failure occurs:
```
✗ FAILURE detected in iteration #1234
Failure count: 5 out of 1234
Failure rate: 0.41%
java.lang.RuntimeException: Secrets do NOT match - encap key: ea 3f 2c 1a 5b 7d 9e 0f... vs decap key: 95 4a 6b 2c 8d 1e 3f 7a...
    at ibm.jceplus.junit.openjceplus.TestPQCKeyInteropStressLoop.testKEMAutoKeyConversion(...)
```

## Stopping the Test

Press `Ctrl+C` to stop the continuous loop.

## Test Coverage

The stress test includes:

1. **KEM Auto Key Conversion** - Tests automatic key conversion between SunJCE and OpenJCEPlus
2. **KEM Interop (Plus to SunJCE)** - Tests OpenJCEPlus key creation with SunJCE operations
3. **KEM Interop (SunJCE to Plus)** - Tests SunJCE key creation with OpenJCEPlus operations
4. **ML-KEM Empty Params** - Tests ML-KEM-512, ML-KEM-768, ML-KEM-1024 with no from/to parameters
5. **ML-KEM All Algorithms** - Tests ML-KEM, ML-KEM-512, ML-KEM-768, ML-KEM-1024 with full parameters
6. **ML-DSA Signature Interop** - Tests ML-DSA-44, ML-DSA-65, ML-DSA-87 signature verification

## Debugging Tips

1. **Increase verbosity**: Modify the test to print more details about key bytes
2. **Add delays**: Increase the `Thread.sleep(100)` value to slow down execution
3. **Limit iterations**: Add a counter to stop after N iterations for debugging
4. **Focus on specific tests**: Comment out tests that are passing to focus on failures

## Expected Behavior

- The test should run indefinitely without failures
- If intermittent failures occur, they will be caught and reported
- The failure rate helps identify how frequently the issue occurs

## Notes

- This is a stress test designed to run for extended periods
- The test uses a 100ms delay between iterations to prevent system overload
- All test methods throw exceptions on failure for easy detection
- Hex output is limited to first 8 bytes for readability