#!/bin/bash

# PQC Key Interop Stress Test Runner
# Compiles and runs the standalone stress test

set -e

echo "=================================="
echo "PQC Key Interop Stress Test"
echo "=================================="
echo ""

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
echo "Java version: $(java -version 2>&1 | head -n 1)"

if [ "$JAVA_VERSION" -lt 21 ]; then
    echo "ERROR: Java 21 or later is required (KEM API)"
    exit 1
fi

# Check if target/classes exists
if [ ! -d "target/classes" ]; then
    echo "ERROR: target/classes not found"
    echo "Please compile OpenJCEPlus first with: mvn compile"
    exit 1
fi

# Compile the stress test
echo ""
echo "Compiling PQCKeyInteropStressTest.java..."
javac -cp target/classes PQCKeyInteropStressTest.java

if [ $? -ne 0 ]; then
    echo "ERROR: Compilation failed"
    exit 1
fi

echo "✓ Compilation successful"
echo ""
echo "Starting stress test (Press Ctrl+C to stop)..."
echo ""

# Run the test
java -cp .:target/classes PQCKeyInteropStressTest

# Made with Bob
