@echo off
REM PQC Key Interop Stress Test Runner for Windows
REM Compiles and runs the standalone stress test

echo ==================================
echo PQC Key Interop Stress Test
echo ==================================
echo.

REM Check if target\classes exists
if not exist "target\classes" (
    echo ERROR: target\classes not found
    echo Please compile OpenJCEPlus first with: mvn compile
    exit /b 1
)

REM Compile the stress test
echo Compiling PQCKeyInteropStressTest.java...
javac -cp target\classes PQCKeyInteropStressTest.java

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo [32m✓ Compilation successful[0m
echo.
echo Starting stress test (Press Ctrl+C to stop)...
echo.

REM Run the test
java -cp .;target\classes PQCKeyInteropStressTest

@REM Made with Bob
