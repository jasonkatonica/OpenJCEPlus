# PQC Key Interop Stress Test

## Overview

`PQCKeyInteropStressTest.java` is a **completely standalone** stress test that reproduces intermittent PQC (Post-Quantum Cryptography) key interoperability failures between OpenJCEPlus and SunJCE providers.

## What It Tests

This test continuously loops to catch race conditions or intermittent issues in:

1. **KEM Auto Key Conversion** - SunJCE keys used with OpenJCEPlus KEM operations
2. **KEM Interop (Plus→SunJCE)** - OpenJCEPlus keys converted to SunJCE
3. **KEM Interop (SunJCE→Plus)** - SunJCE keys converted to OpenJCEPlus with encapsulation/decapsulation
4. **ML-KEM Empty Params** - ML-KEM-512/768/1024 with no from/to parameters
5. **ML-KEM All Algorithms** - ML-KEM, ML-KEM-512/768/1024 with full parameters
6. **ML-DSA Signatures** - ML-DSA-44/65/87 signature verification across providers

## Failures Being Reproduced

Based on Jenkins test failures:
- `testPQCKeyGenKEMAutoKeyConvertion` - Secrets do NOT match
- `testKEMInteropKeyPlusAll` - Secrets do NOT match for ML-KEM variants
- `testMLKEMInteropEmptyParamsWithNamedParameterSpec` - Keys do not match
- `testPQCKeyGenKEM_Interop` - Key encoding mismatches
- `testPQCKeyGenKEM_PlusToInteropRAW` - Key conversion failures
- `testSignInteropKeysPlusSignVerify` - Signature verification failures

## Requirements

- **Java 21 or later** (KEM API was introduced in Java 21)
- OpenJCEPlus compiled in `target/classes`

## Quick Start

### 1. Compile

```bash
javac -cp target/classes PQCKeyInteropStressTest.java
```

### 2. Run

```bash
java -cp .:target/classes PQCKeyInteropStressTest
```

**On Windows:**
```cmd
java -cp .;target/classes PQCKeyInteropStressTest
```

### 3. Stop

Press `Ctrl+C` to stop the continuous loop.

## Example Output

### Successful Iteration
```
================================================================================
Iteration #1234 - Failures so far: 0
================================================================================

[Test] KEM Auto Key Conversion (SunJCE -> OpenJCEPlus)
  ✓ Secrets match

[Test] KEM Interop (OpenJCEPlus keys -> SunJCE operations)
  ✓ Key conversion successful

[Test] KEM Interop (SunJCE keys -> OpenJCEPlus operations)
  ✓ Secrets match

[Test] ML-KEM Empty Params: ML-KEM-512
  ✓ Keys match for ML-KEM-512

[Test] ML-KEM Empty Params: ML-KEM-768
  ✓ Keys match for ML-KEM-768

[Test] ML-KEM Empty Params: ML-KEM-1024
  ✓ Keys match for ML-KEM-1024

[Test] KEM Interop Key Plus All: ML-KEM
  ✓ Secrets match for ML-KEM

[Test] KEM Interop Key Plus All: ML-KEM-512
  ✓ Secrets match for ML-KEM-512

[Test] KEM Interop Key Plus All: ML-KEM-768
  ✓ Secrets match for ML-KEM-768

[Test] KEM Interop Key Plus All: ML-KEM-1024
  ✓ Secrets match for ML-KEM-1024

[Test] ML-DSA Signature Interop: ML-DSA-44
  ✓ Signature verified for ML-DSA-44

[Test] ML-DSA Signature Interop: ML-DSA-65
  ✓ Signature verified for ML-DSA-65

[Test] ML-DSA Signature Interop: ML-DSA-87
  ✓ Signature verified for ML-DSA-87

✓ Iteration #1234 PASSED
```

### When Failure Occurs
```
✗ FAILURE detected in iteration #1234
Failure count: 5 out of 1234
Failure rate: 0.41%
java.lang.RuntimeException: Secrets do NOT match - encap key: ea 3f 2c 1a 5b 7d 9e 0f... vs decap key: 95 4a 6b 2c 8d 1e 3f 7a...
    at PQCKeyInteropStressTest.testKEMAutoKeyConversion(PQCKeyInteropStressTest.java:145)
    at PQCKeyInteropStressTest.main(PQCKeyInteropStressTest.java:78)
```

## Customization

### Change Iteration Delay

Edit line 108 in `PQCKeyInteropStressTest.java`:
```java
Thread.sleep(100);  // Change to desired milliseconds
```

### Limit Iterations

Add a counter check in the main loop (around line 67):
```java
while (totalIterations < 10000) {  // Stop after 10000 iterations
```

### Focus on Specific Tests

Comment out tests you don't want to run (lines 78-103).

## Troubleshooting

### Error: "Failed to load OpenJCEPlus provider"

**Solution:** Make sure OpenJCEPlus is compiled:
```bash
mvn compile
```

Then verify `target/classes` contains the compiled provider.

### Error: "KEM cannot be resolved"

**Solution:** You need Java 21 or later. Check your version:
```bash
java -version
```

### ClassNotFoundException

**Solution:** Ensure the classpath includes both the current directory and target/classes:
```bash
# Linux/Mac
java -cp .:target/classes PQCKeyInteropStressTest

# Windows
java -cp .;target/classes PQCKeyInteropStressTest
```

## Understanding the Output

- **Iteration #** - Current test iteration number
- **Failures so far** - Total number of failures detected
- **Failure rate** - Percentage of iterations that failed
- **✓** - Test passed
- **✗** - Test failed with details

## Notes

- This test runs **indefinitely** until stopped with Ctrl+C
- Each iteration takes approximately 100ms (plus test execution time)
- The test is designed to catch **intermittent** failures that may occur rarely
- Hex output shows first 8 bytes of keys for debugging
- All tests use the same providers: OpenJCEPlus and SunJCE/SUN

## Why This Test Exists

The original Jenkins test suite showed intermittent failures where:
- Encapsulated and decapsulated secrets don't match
- Key encodings differ between providers
- Signature verification fails randomly

This standalone test helps reproduce these issues by running continuously, making it easier to:
1. Identify the failure pattern
2. Debug the root cause
3. Verify fixes