# Memory Corruption Detection for OpenJCEPlus

This document describes how to use memory corruption detection tools for the OpenJCEPlus native library.

## Overview

### Active Tools in CI

**UndefinedBehaviorSanitizer (UBSan)** - Enabled by default in CI builds

Detects undefined behavior including:
- Integer overflow (signed and unsigned)
- Null pointer dereference
- Misaligned pointer access
- Division by zero
- Invalid shifts
- Out-of-bounds array access
- Invalid type casts
- Invalid function calls

**Additional Compile-Time Protections** - Always enabled

- **`-D_FORTIFY_SOURCE=2`**: Compile-time and runtime buffer overflow detection (aborts on error)
- **`-fstack-protector-strong`**: Stack smashing protection (aborts on stack corruption)
- **`-fno-omit-frame-pointer`**: Better stack traces for debugging

### Why Not AddressSanitizer (ASan)?

AddressSanitizer is **incompatible with the JVM** due to shadow memory address space conflicts. When ASan tries to initialize its shadow memory, it conflicts with the JVM's memory layout:

```
Shadow memory range interleaves with an existing memory mapping. ASan cannot proceed correctly.
```

**For memory error detection** (buffer overflows, use-after-free, memory leaks), use **Valgrind** instead (see below).

### Summary of Error Detection

| Tool | What It Detects | Reports Saved? | Continues on Error? | Active in CI? |
|------|----------------|----------------|---------------------|---------------|
| **UBSan** | Undefined behavior, integer overflows, null deref | ✅ Yes (files) | ✅ Yes | ✅ Yes (all tests) |
| **Fortify Source** | Buffer overflows | ❌ No (aborts) | ❌ No (aborts) | ✅ Yes (all tests) |
| **Stack Protector** | Stack corruption | ❌ No (aborts) | ❌ No (aborts) | ✅ Yes (all tests) |
| **ASan** | Memory errors, leaks | N/A | N/A | ❌ No (JVM incompatible) |
| **Valgrind** | Memory errors, leaks | ✅ Yes (files) | ✅ Yes | ✅ Yes (subset) |

## Enabling Sanitizers

### For Local Development

To build the native library with sanitizers enabled on Linux x86-64:

```bash
export PLATFORM=x86-linux64
export ENABLE_SANITIZERS=1
export JAVA_HOME=/path/to/jdk
export GSKIT_HOME=/path/to/gskit

cd src/main/native
make -f jgskit.mak clean
make -f jgskit.mak
```

### For GitHub Actions

UBSan is automatically enabled in the GitHub Actions workflow for Linux x86-64 builds. The workflow sets:

- `ENABLE_SANITIZERS=1` to enable compilation with UBSan and additional protections
- `UBSAN_OPTIONS` for UndefinedBehaviorSanitizer runtime configuration with log file output
- Post-test checks that display any detected errors
- Artifact upload to preserve error reports

The sanitizer runtime library is automatically loaded when the native library (`libjgskit.so`) is loaded by the JVM.

## Runtime Configuration

### UndefinedBehaviorSanitizer Options (UBSAN_OPTIONS)

**GitHub Actions Configuration:**
```bash
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:suppressions=${{ github.workspace }}/.github/ubsan.supp:log_path=${{ github.workspace }}/target/ubsan-reports/ubsan"
```

**Local Development Configuration:**
```bash
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:suppressions=.github/ubsan.supp:log_path=target/ubsan-reports/ubsan"
```

**Option Descriptions:**
- `print_stacktrace=1`: Print stack traces for errors
- `halt_on_error=0`: Continue after first error to find multiple issues
- `suppressions=.github/ubsan.supp`: Path to suppressions file
- `log_path=target/ubsan-reports/ubsan`: Save reports to files (one per process)

**Additional useful options:**
- `verbosity=1`: Increase verbosity level
- `halt_on_error=1`: Stop at first error (useful to fail builds)

## Suppressions

If you encounter false positives or intentional undefined behavior, add suppressions to `.github/ubsan.supp`:

```
# Suppress specific checks in functions
<check_name>:function_name_pattern

# Example: Suppress integer overflow in specific functions
signed-integer-overflow:*calculate_hash*
alignment:*JVM_*
```

Available check names: `alignment`, `bool`, `bounds`, `enum`, `float-cast-overflow`, `float-divide-by-zero`, `function`, `integer-divide-by-zero`, `nonnull-attribute`, `null`, `object-size`, `pointer-overflow`, `return`, `returns-nonnull-attribute`, `shift`, `signed-integer-overflow`, `unreachable`, `unsigned-integer-overflow`, `vla-bound`, `vptr`

## Running Tests with Sanitizers

### Maven Tests

When UBSan is enabled, run tests normally:

```bash
mvn clean install -Dock.library.path=/path/to/ock
```

UBSan will automatically detect and report undefined behavior during test execution.

**Behavior when errors are detected:**

1. **Tests continue running**: With `halt_on_error=0`, UBSan reports all errors but doesn't stop execution
2. **Errors logged to files**: Reports are saved to `target/ubsan-reports/ubsan.*` files
3. **Console output**: Errors are also printed to stderr during test execution
4. **GitHub Actions**:
   - Errors are displayed as warnings in the workflow
   - Reports are archived as artifacts for download
   - Build continues but warnings are visible in the Actions UI
5. **Maven exit code**: Tests may still pass even with UBSan errors (warnings only)

**To make UBSan errors fail the build**, set `halt_on_error=1` in `UBSAN_OPTIONS`, but this will stop at the first error instead of finding all issues.

### Interpreting UBSan Results

When undefined behavior is detected, UBSan will print:

1. **Error type**: e.g., "signed integer overflow", "null pointer dereference"
2. **Location**: File and line number where the error occurred
3. **Stack trace**: Call stack leading to the error

Example output:
```
/path/to/file.c:123:45: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x7f8b8c0d4e89 in function_name /path/to/file.c:123
    #1 0x7f8b8c0d5123 in caller_function /path/to/file.c:456
```

## Performance Impact

UBSan adds minimal runtime overhead:

- **UndefinedBehaviorSanitizer**: ~20% slowdown
- **Fortify Source**: Negligible overhead
- **Stack Protector**: <5% overhead

This is acceptable for testing and can even be used in development builds.

## Compiler Requirements

- GCC 4.9+ or Clang 3.3+ for UndefinedBehaviorSanitizer
- The GitHub Actions workflow uses Ubuntu 22.04 with GCC 11+

## Using Valgrind for Memory Error Detection

Since AddressSanitizer is incompatible with JVM, use Valgrind for detecting memory errors.

### Valgrind in CI

**Valgrind is now active in GitHub Actions!** A separate job runs a subset of tests under Valgrind:

- **Job**: `Valgrind-Memory-Check`
- **Tests**: `TestAESGCM` (representative test suite)
- **Reports**: Saved to `target/valgrind-reports/` and archived as artifacts
- **Performance**: Runs slower (~10-50x) but provides comprehensive memory error detection

The CI job uses a wrapper script that runs the JVM under Valgrind, allowing full memory analysis of both Java and native code.

### What Valgrind Detects

- Memory leaks (definite, possible, reachable)
- Buffer overflows (heap and stack)
- Use-after-free
- Invalid memory access
- Uninitialized memory use
- Invalid pointer operations

### Running Valgrind Locally with Maven

For comprehensive local testing, you can run Maven tests under Valgrind using the same approach as CI:

```bash
# Install Valgrind
sudo apt-get install valgrind

# Create reports directory
mkdir -p target/valgrind-reports

# Create wrapper script (same as CI uses)
cat > java-valgrind << 'EOF'
#!/bin/bash
REAL_JAVA="$JAVA_HOME/bin/java"
VALGRIND_OPTS="--leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  --verbose \
  --log-file=target/valgrind-reports/valgrind-%p.log \
  --suppressions=.github/valgrind.supp \
  --error-exitcode=0"
exec valgrind $VALGRIND_OPTS "$REAL_JAVA" "$@"
EOF

chmod +x java-valgrind

# Run Maven tests with Valgrind wrapper
mvn test \
  -Dock.library.path=/path/to/ock \
  -DjavaExecutable=./java-valgrind \
  -Dtest=ibm.jceplus.junit.openjceplus.TestAESGCM

# Check for errors
if grep -q "ERROR SUMMARY: [1-9]" target/valgrind-reports/*.log; then
  echo "⚠️ Valgrind detected memory errors - see reports in target/valgrind-reports/"
else
  echo "✅ No Valgrind errors detected"
fi
```

**How it works:**
1. The wrapper script (`java-valgrind`) replaces the Java executable
2. Maven Surefire uses this wrapper via `-DjavaExecutable` parameter
3. Every forked JVM process runs under Valgrind
4. Reports are saved with process ID in filename (`valgrind-12345.log`)

**Key Options:**
- `--log-file=path/valgrind-%p.log`: Save reports to files (%p = process ID)
- `--error-exitcode=0`: Continue running even with errors (default behavior)
- `--error-exitcode=1`: Exit with error code if issues found (fails build)

**Performance Note**: Valgrind is much slower (~10-50x) but more thorough than ASan.

### Valgrind Suppressions

Create `.github/valgrind.supp` for false positives:

```
{
   JVM_Internal_Leak
   Memcheck:Leak
   ...
   fun:*JVM_*
}

{
   OpenSSL_Known_Issue
   Memcheck:Cond
   ...
   obj:*/libcrypto.so*
}
```

## Troubleshooting

### UBSan Library Not Found

If you see errors about missing UBSan library:

```bash
# Install UBSan library
sudo apt-get install libubsan1
```

### False Positives

If you encounter false positives:

1. Verify the issue is actually a false positive
2. Add appropriate suppressions to `.github/ubsan.supp`
3. Document why the suppression is needed

## Best Practices

1. **Run UBSan regularly**: Enabled by default in CI/CD
2. **Fix issues immediately**: Don't accumulate UBSan warnings
3. **Test thoroughly**: Run comprehensive test suites
4. **Document suppressions**: Always document why a suppression is needed
5. **Use Valgrind periodically**: Run Valgrind tests weekly or before releases

## Additional Tools

Recommended complementary tools:

- **Valgrind**: Essential for memory error detection (use instead of ASan)
- **Clang Static Analyzer**: Static analysis for finding bugs
- **Cppcheck**: Static analysis tool
- **GDB**: Debugger for investigating crashes

## References

- [UndefinedBehaviorSanitizer Documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [Valgrind Documentation](https://valgrind.org/docs/manual/manual.html)
- [GCC Instrumentation Options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)