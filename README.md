# PoC for BIP-32/BIP-44 Compliance Gaps in FB mpc-lib

**Disclaimer:** This repository contains Proof-of-Concept (PoC) code and analysis related to potential vulnerabilities identified in the publicly available `fireblocks/mpc-lib` repository (as of April 2024). This information is shared for educational and research purposes only and demonstrates specific deviations from published standards based on the reviewed library code. It may **not** reflect the state or behavior of FB current production systems. Do not use this code maliciously. 

## Overview

This repository provides code to demonstrate and reproduce three specific compliance gaps identified during a review of the Hierarchical Deterministic (HD) wallet derivation logic within the Fireblocks `mpc-lib`. These gaps relate to non-adherence to the BIP-32 and BIP-44 standards.

The goal is to provide clear, reproducible evidence of these issues based on the library's code.

## Vulnerabilities Demonstrated

1.  **Missing BIP-32 Validity Checks (Critical Impact):**
    *   **Issue:** The core HD derivation logic (`add_scalars`, `add_points`, etc., used by `derive_next_key_level_`) fails to check if derived private keys are zero or if derived public keys are the point-at-infinity, returning success even for these invalid keys, violating the BIP-32 standard.
    *   **Impact:** Potential generation of unspendable wallets, leading to permanent fund loss if used in production.
    *   **PoC Test:** `test_bip32_checks.cpp`

2.  **Incorrect BIP-44 Path Hardening (Critical Impact):**
    *   **Issue:** The `build_bip44_path` helper function fails to apply mandatory hardening (`+ 0x80000000`) to the `purpose'`, `coin_type'`, and `account'` levels (indices 0, 1, 2), violating the BIP-44 standard. The defined `BIP44` constant is also non-hardened.
    *   **Impact:** Generates non-standard wallets, breaking interoperability and standard recovery methods (e.g., with hardware wallets), potentially weakening security boundaries.
    *   **PoC Test:** `test_bip44_paths.cpp`

3.  **Missing NULL Context Check (Medium Impact):**
    *   **Issue:** The primary derivation functions (`derive_*_generic`) do not check if the provided elliptic curve context pointer (`ctx`) is NULL before dereferencing it.
    *   **Impact:** Leads to a crash (NULL pointer dereference, Segmentation Fault) if the context is not initialized, causing Denial of Service for the calling application.
    *   **PoC Test:** `test_null_context.cpp`

## Repository Contents

*   `test_bip32_checks.cpp`: PoC code for Issue 1.
*   `test_bip44_paths.cpp`: PoC code for Issue 2.
*   `test_null_context.cpp`: PoC code for Issue 3.
*   `CMakeLists.txt`: CMake build instructions to compile the tests against a local build of `mpc-lib`.
*   `README.md`: This file.
*   `.gitignore`: Standard ignores for C++/CMake build artifacts.
*   `LICENSE`: MIT License for the PoC code in this repository.

**Note:** This repository does **not** contain the `fireblocks/mpc-lib` source code itself. You must clone and build it separately as per the setup instructions.

## Prerequisites

*   **Linux Environment:** Tested on WSL (Ubuntu 22.04). May work on other Linux distributions.
*   **Git:** For cloning repositories.
*   **CMake:** Version 3.10 or higher. (`sudo apt install cmake`)
*   **C++ Compiler:** Supporting C++11 (e.g., `g++` or `clang++`). (`sudo apt install build-essential`)
*   **Make:** Build tool used by CMake. (`sudo apt install build-essential`)
*   **OpenSSL Development Libraries:** Required by `mpc-lib`. (`sudo apt install libssl-dev`)
*   **UUID Development Library:** Required by `mpc-lib`. (`sudo apt install uuid-dev`)

## Setup and Build Instructions

These steps assume you are working within a suitable Linux/WSL environment with the prerequisites installed.

1.  **Clone This PoC Repository:**
    ```bash
    git clone https://github.com/mickymultani/mpc-cmp-testing.git 
    cd mpc-cmp-testing
    ```

2.  **Clone Target `fireblocks/mpc-lib` Repository:**
    Clone the Fireblocks library *inside* the PoC repository directory. The `CMakeLists.txt` file expects this structure (`mpc-cmp-testing/mpc-lib/`).
    ```bash
    git clone https://github.com/fireblocks/mpc-lib.git
    ```

3.  **Build Target `fireblocks/mpc-lib`:**
    Compile the Fireblocks library first. This generates the `libcosigner.so` file needed by the tests.
    ```bash
    cd mpc-lib      # Enter the library directory
    mkdir build     # Create build directory for the library
    cd build
    cmake ..        # Configure the library build
    make -j$(nproc) # Compile the library (using multiple cores)
    cd ../..        # Return to the root of the PoC repo (mpc-cmp-testing/)
    ```
    *   **Verify:** Ensure the build completes without errors and that the shared library exists at `mpc-lib/build/src/common/libcosigner.so`. If not, troubleshoot the `mpc-lib` build process.

4.  **Build PoC Tests:**
    Now, configure and build the test executables using the `CMakeLists.txt` provided in this repository.
    ```bash
    mkdir build     # Create build directory for the tests (different from mpc-lib's build dir)
    cd build
    cmake ..        # Configure the test build (reads ../CMakeLists.txt)
    make -j$(nproc) # Compile the tests
    ```
    *   **Verify:** Ensure this build completes without errors. This step compiles your `.cpp` files and links them against `libcosigner.so`. The executables (`test_bip32_checks`, `test_bip44_paths`, `test_null_context`) will be created inside `mpc-cmp-testing/build/`.

## Running the Tests

Execute the compiled tests from the PoC build directory (`mpc-cmp-testing/build/`).

1.  **Ensure you are in the test build directory:**
    ```bash
    cd ~/path/to/mpc-cmp-testing/build # Adjust path as needed
    ```

2.  **Run Test 1 (BIP-32 Checks):**
    ```bash
    ./test_bip32_checks
    ```

3.  **Run Test 2 (BIP-44 Paths):**
    ```bash
    ./test_bip44_paths
    ```

4.  **Run Test 3 (NULL Context):**
    ```bash
    ./test_null_context
    ```

## Interpreting Test Results

*   **`test_bip32_checks`:**
    *   **Expected Success (Vulnerability Present):** The program should complete successfully (exit code 0) and print ">>> Proof 1 Verdict: VULNERABILITY CONFIRMED <<<" and ">>> Proof 2 Verdict: VULNERABILITY CONFIRMED <<<". This indicates the library returned success despite generating invalid keys.
    *   **Unexpected Failure:** If it prints errors or "Proof Verdict: FAILED", the vulnerability might be fixed in the version of `mpc-lib` you used, or there was an error during the test setup/execution.

*   **`test_bip44_paths`:**
    *   **Expected Success (Vulnerability Present):** The program should complete (likely with a non-zero exit code indicating errors) and print "FAIL (Hardening Incorrect!)" for indices 0, 1, and 2. The final verdict should state "VULNERABILITY CONFIRMED".
    *   **Unexpected Result:** If it prints "VULNERABILITY NOT CONFIRMED" or other errors, the issue might be fixed, or the test setup was incorrect.

*   **`test_null_context`:**
    *   **Expected Success (Vulnerability Present):** The program should **crash** immediately after printing `>>> EXPECTING A CRASH... <<<`. The shell will typically report `Segmentation fault (core dumped)`.
    *   **Unexpected Result:** If the program prints `!!! PROOF VERDICT: FAILED - Program did NOT crash! !!!` and exits normally (exit code 1), the vulnerability is likely not present or has been fixed in the version tested.

## License

The Proof-of-Concept code within this repository (`tests/*.cpp`, `CMakeLists.txt`) is licensed under the [MIT License](LICENSE).

The underlying `fireblocks/mpc-lib` repository has its own license (Apache 2.0 as of writing), which applies to that code.
