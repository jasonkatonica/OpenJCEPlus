# Memory Sanitizers for OpenJCEPlus

This document describes how to use memory sanitizers to detect memory corruption issues in the OpenJCEPlus native library.

## Overview

Memory sanitizers are powerful tools for detecting various types of memory-related bugs:

- **AddressSanitizer (ASan)**: Detects memory errors including:
  - Buffer overflows (heap, stack, and global)
  - Use-after-free
  - Use-after-return
  - Use-after-scope
  - Double-free
  - Invalid pointer pairs
  - Memory leaks (via LeakSanitizer)

- **UndefinedBehaviorSanitizer (UBSan)**: Detects undefined behavior including:
  - Integer overflow
  - Null pointer dereference
  - Misaligned pointer access
  - Division by zero
  - Invalid shifts

- **LeakSanitizer (LSan)**: Detects memory leaks (integrated with ASan)

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

Sanitizers are automatically enabled in the GitHub Actions workflow for Linux x86-64 builds. The workflow sets:

- `ENABLE_SANITIZERS=1` to enable compilation with sanitizer flags
- `ASAN_OPTIONS` for AddressSanitizer runtime configuration
- `UBSAN_OPTIONS` for UndefinedBehaviorSanitizer runtime configuration
- `LSAN_OPTIONS` for LeakSanitizer runtime configuration

## Runtime Configuration

### AddressSanitizer Options (ASAN_OPTIONS)

The following options are configured in the GitHub Actions workflow:

```bash
export ASAN_OPTIONS="detect_leaks=1:check_initialization_order=1:strict_init_order=1:detect_stack_use_after_return=1:detect_invalid_pointer_pairs=2:strict_string_checks=1"
```

- `detect_leaks=1`: Enable leak detection
- `check_initialization_order=1`: Detect initialization order bugs
- `strict_init_order=1`: Strict checking of initialization order
- `detect_stack_use_after_return=1`: Detect use-after-return bugs
- `detect_invalid_pointer_pairs=2`: Detect invalid pointer comparisons
- `strict_string_checks=1`: Enable strict string function checks

Additional useful options:
- `halt_on_error=0`: Continue after first error (useful for finding multiple issues)
- `log_path=/path/to/asan.log`: Write output to file instead of stderr
- `verbosity=1`: Increase verbosity level

### UndefinedBehaviorSanitizer Options (UBSAN_OPTIONS)

```bash
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"
```

- `print_stacktrace=1`: Print stack traces for errors
- `halt_on_error=0`: Continue after first error

### LeakSanitizer Options (LSAN_OPTIONS)

```bash
export LSAN_OPTIONS="suppressions=.github/lsan.supp:print_suppressions=0"
```

- `suppressions=.github/lsan.supp`: Path to suppressions file
- `print_suppressions=0`: Don't print suppressed leaks

## Suppressions

If you encounter false positives or intentional leaks, you can add suppressions to `.github/lsan.supp`:

```
# Suppress leaks from specific functions
leak:function_name_pattern

# Example: Suppress JVM internal leaks
leak:*JVM_*
leak:*Java_*
```

## Running Tests with Sanitizers

### Maven Tests

When sanitizers are enabled, run tests normally:

```bash
mvn clean install -Dock.library.path=/path/to/ock
```

The sanitizers will automatically detect and report issues during test execution.

### Interpreting Results

When a memory error is detected, the sanitizer will print:

1. **Error type**: e.g., "heap-buffer-overflow", "use-after-free"
2. **Stack trace**: Where the error occurred
3. **Memory allocation trace**: Where the problematic memory was allocated
4. **Shadow bytes**: Memory state around the error location

Example output:
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60300000eff4 at pc 0x7f8b8c0d4e8a bp 0x7ffc9c8e7a50 sp 0x7ffc9c8e7a48
WRITE of size 4 at 0x60300000eff4 thread T0
    #0 0x7f8b8c0d4e89 in function_name /path/to/file.c:123
    #1 0x7f8b8c0d5123 in caller_function /path/to/file.c:456
    ...
```

## Performance Impact

Sanitizers add significant runtime overhead:

- **AddressSanitizer**: ~2x slowdown, 2-3x memory overhead
- **UndefinedBehaviorSanitizer**: ~20% slowdown
- **Combined**: ~2-3x slowdown

This is acceptable for testing but should not be used in production builds.

## Compiler Requirements

- GCC 4.8+ or Clang 3.1+ for AddressSanitizer
- GCC 4.9+ or Clang 3.3+ for UndefinedBehaviorSanitizer
- The GitHub Actions workflow uses Ubuntu 22.04 with GCC 11+

## Troubleshooting

### Sanitizer Library Not Found

If you see errors about missing sanitizer libraries:

```bash
# Install sanitizer libraries
sudo apt-get install libasan6 libubsan1 liblsan0
```

### False Positives

If you encounter false positives:

1. Verify the issue is actually a false positive
2. Add appropriate suppressions to `.github/lsan.supp`
3. Document why the suppression is needed

### Performance Issues

If tests are too slow with sanitizers:

1. Run a subset of tests: `-Dtest=SpecificTest`
2. Disable leak detection: `ASAN_OPTIONS=detect_leaks=0`
3. Use faster detection: `ASAN_OPTIONS=fast_unwind_on_malloc=1`

## Best Practices

1. **Run sanitizers regularly**: Enable in CI/CD to catch issues early
2. **Fix issues immediately**: Don't accumulate sanitizer warnings
3. **Test thoroughly**: Run comprehensive test suites with sanitizers
4. **Document suppressions**: Always document why a suppression is needed
5. **Review reports**: Carefully analyze all sanitizer reports

## Additional Tools

Consider using these complementary tools:

- **Valgrind**: More thorough but slower memory checking
- **Electric Fence**: Detects buffer overruns and underruns
- **Dr. Memory**: Windows-compatible memory debugger

## References

- [AddressSanitizer Documentation](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [UndefinedBehaviorSanitizer Documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [LeakSanitizer Documentation](https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer)