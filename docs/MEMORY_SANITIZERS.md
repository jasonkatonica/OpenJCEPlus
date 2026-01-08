# Memory Corruption Detection for OpenJCEPlus

This document describes how to use memory corruption detection tools for the OpenJCEPlus native library.

## Overview

### UndefinedBehaviorSanitizer (UBSan)

UBSan is enabled by default in CI builds and detects undefined behavior including:
- Integer overflow (signed and unsigned)
- Null pointer dereference
- Misaligned pointer access
- Division by zero
- Invalid shifts
- Out-of-bounds array access
- Invalid type casts
- Invalid function calls

**Why not AddressSanitizer (ASan)?**

AddressSanitizer is incompatible with the JVM due to shadow memory address space conflicts. When ASan tries to initialize its shadow memory, it conflicts with the JVM's memory layout, causing the error:

```
Shadow memory range interleaves with an existing memory mapping. ASan cannot proceed correctly.
```

For memory error detection (buffer overflows, use-after-free, etc.), use **Valgrind** instead (see below).

### Additional Protections

The build also enables:
- **`-D_FORTIFY_SOURCE=2`**: Compile-time and runtime buffer overflow detection
- **`-fstack-protector-strong`**: Stack smashing protection
- **`-fno-omit-frame-pointer`**: Better stack traces for debugging

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
- `UBSAN_OPTIONS` for UndefinedBehaviorSanitizer runtime configuration

The sanitizer runtime library is automatically loaded when the native library (`libjgskit.so`) is loaded by the JVM.

## Runtime Configuration

### UndefinedBehaviorSanitizer Options (UBSAN_OPTIONS)

```bash
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:suppressions=.github/ubsan.supp"
```

- `print_stacktrace=1`: Print stack traces for errors
- `halt_on_error=0`: Continue after first error to find multiple issues
- `suppressions=.github/ubsan.supp`: Path to suppressions file

Additional useful options:
- `log_path=/path/to/ubsan.log`: Write output to file instead of stderr
- `verbosity=1`: Increase verbosity level

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

Since AddressSanitizer is incompatible with JVM, use Valgrind for detecting memory errors:

```bash
# Install Valgrind
sudo apt-get install valgrind

# Run tests with Valgrind
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
  --suppressions=.github/valgrind.supp \
  mvn test -Dock.library.path=/path/to/ock
```

Valgrind detects:
- Memory leaks
- Buffer overflows
- Use-after-free
- Invalid memory access
- Uninitialized memory use

**Note**: Valgrind is much slower (~10-50x) but more thorough than ASan.

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