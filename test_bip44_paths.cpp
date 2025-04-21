/**
 * Test Name: test_bip44_paths
 *
 * Objective:
 *   Demonstrate that the Fireblocks MPC library's `build_bip44_path` helper
 *   function generates paths that do NOT conform to the BIP-44 standard's
 *   hardening requirements.
 *
 * Vulnerability Tested:
 *   Incorrect BIP-44 path generation: Missing hardening for the purpose',
 *   coin_type', and account' levels.
 *
 * Expected Outcome:
 *   The test calls `build_bip44_path` and compares the resulting path elements
 *   against the expected *correct* BIP-44 path. The output will explicitly show
 *   the generated vs. expected values for each path element, highlighting the
 *   missing hardening bits (0x80000000) on the first three elements.
 *
 * Impact:
 *   - Non-standard wallets are generated.
 *   - Interoperability Failure: Standard wallets/tools cannot discover or recover
 *     funds using these non-standard paths.
 *   - Reduced Security: Breaks the intended isolation between accounts provided
 *     by hardened derivation.
 *   - Non-compliance with the BIP-44 standard.
 */

#include <iostream>     // For std::cout, std::cerr
#include <cstdint>      // For uint32_t
#include <cstring>      // For memcmp
#include <cassert>      // For assert (optional)
#include <iomanip>      // For std::hex, std::showbase

// --- FIX: Define COSIGNER_EXPORT as empty before including library headers ---
#define COSIGNER_EXPORT

// --- Fireblocks mpc-lib Includes ---
// Contains build_bip44_path function signature and Bip44Path type definition
// Also defines BIP44_PATH_LENGTH
#include "blockchain/mpc/hd_derive.h"

// --- Constants ---
// Define the hardening bit for clarity
const uint32_t HARDENED_BIT = 0x80000000;
// REMOVED redefinition of BIP44_PATH_LENGTH


// --- Helper Functions ---

// Prints a single path element, comparing actual vs expected and checking hardening.
void print_path_element_comparison(int index, uint32_t actual, uint32_t expected_correct) {
    bool actual_is_hardened = (actual & HARDENED_BIT) != 0;
    bool expected_is_hardened = (expected_correct & HARDENED_BIT) != 0;
    bool value_matches = (actual == expected_correct);
    bool hardening_matches = (actual_is_hardened == expected_is_hardened);

    std::cout << "  Index " << std::setw(1) << index << ": "
              << "Actual= " << std::hex << std::showbase << std::setw(10) << std::left << actual << std::dec
              << " (Hardened: " << (actual_is_hardened ? "YES" : "NO ") << ") | " // Pad NO for alignment
              << "Expected= " << std::hex << std::showbase << std::setw(10) << std::left << expected_correct << std::dec
              << " (Hardened: " << (expected_is_hardened ? "YES" : "NO ") << ")";

    // Report status
    if (value_matches) {
        std::cout << " -> OK" << std::endl;
    } else if (!hardening_matches && index <= 2) { // Indices 0, 1, 2 MUST be hardened
        std::cout << " -> FAIL (Hardening Incorrect!)" << std::endl;
    } else if (!hardening_matches && index > 2) { // Indices 3, 4 MUST NOT be hardened
         std::cout << " -> FAIL (Hardening Incorrect!)" << std::endl;
    }
    else {
        // This case should only happen if the non-hardened part differs
        std::cout << " -> FAIL (Value Mismatch!)" << std::endl;
    }
}


// --- Main Test Logic ---
int main() {
    std::cout << "===============================================" << std::endl;
    std::cout << "=== Test: Incorrect BIP-44 Path Generation ===" << std::endl;
    std::cout << "===============================================" << std::endl;
    int errors = 0; // Track path mismatches

    // --- Step 1: Define Test Inputs ---
    std::cout << "\n[Step 1] Defining test inputs..." << std::endl;
    uint32_t asset_num = 0;   // Example: Bitcoin coin_type
    uint32_t account = 1;     // Example: Account 1
    uint32_t change = 0;      // Example: External chain
    uint32_t addr_index = 5;  // Example: Address index 5

    std::cout << "Inputs: Purpose=44 (Implicit), CoinType=" << asset_num
              << ", Account=" << account << ", Change=" << change << ", AddressIndex=" << addr_index << std::endl;

    // --- Step 2: Define Expected Correct BIP-44 Path ---
    std::cout << "\n[Step 2] Defining expected CORRECT BIP-44 path..." << std::endl;
    // Use the BIP44 constant defined in hd_derive.h if available, otherwise hardcode 44
    // Assuming hd_derive.h defines 'BIP44' (potentially incorrectly without hardening)
    // Let's calculate the correct purpose value here regardless
    const uint32_t CORRECT_BIP44_PURPOSE = HARDENED_BIT | 44;
    Bip44Path expected_correct_path = {
        CORRECT_BIP44_PURPOSE,      // Purpose 44'
        HARDENED_BIT | asset_num,  // Coin Type 0'
        HARDENED_BIT | account,    // Account 1'
        change,                    // Change 0 (non-hardened)
        addr_index                 // Address Index 5 (non-hardened)
    };
     std::cout << "Expected Correct Path (Hex): " << std::hex << std::showbase
               << expected_correct_path[0] << "/" << expected_correct_path[1] << "/"
               << expected_correct_path[2] << "/" << expected_correct_path[3] << "/"
               << expected_correct_path[4] << std::dec << std::endl;


    // --- Step 3: Call the build_bip44_path function ---
    std::cout << "\n[Step 3] Calling build_bip44_path function..." << std::endl;
    Bip44Path actual_path; // Variable to store the result
    // Call the function using the declared parameters
    hd_derive_status status = build_bip44_path(actual_path, asset_num, account, change, addr_index);

    std::cout << " -> build_bip44_path status code: " << status << " (Expected: " << HD_DERIVE_SUCCESS << ")" << std::endl;

    // --- Step 4: Compare Actual vs Expected Correct Path ---
    std::cout << "\n[Step 4] Comparing actual generated path vs expected correct path:" << std::endl;
    if (status == HD_DERIVE_SUCCESS) {
        bool overall_match = true;
        // Use the constant BIP44_PATH_LENGTH which IS defined in hd_derive.h
        for (int i = 0; i < BIP44_PATH_LENGTH; ++i) {
            print_path_element_comparison(i, actual_path[i], expected_correct_path[i]);
            if (actual_path[i] != expected_correct_path[i]) {
                overall_match = false;
                // Increment error count specifically if required hardening is wrong
                if (i <= 2 && ((actual_path[i] & HARDENED_BIT) == 0)) {
                    errors++;
                }
                 // Also count error if non-hardened indices ARE hardened
                 else if (i > 2 && ((actual_path[i] & HARDENED_BIT) != 0)) {
                     errors++;
                 }
            }
        }

        // Evaluate proof based on comparison
        std::cout << "\n>>> Proof Verdict: " << std::endl;
        if (errors > 0) {
             std::cout << "    VULNERABILITY CONFIRMED <<<" << std::endl;
             std::cout << "    Generated path violates BIP-44 hardening rules on " << errors << " element(s)." << std::endl;
        } else if (!overall_match) {
            // This case implies values differ but hardening might be ok? Unlikely for this bug.
            std::cout << "    UNCERTAIN <<<" << std::endl;
             std::cout << "    Path differs from expected correct path, but no critical hardening errors detected." << std::endl;
             std::cout << "    Please double-check expected values and function logic." << std::endl;
             errors++; // Treat unexpected difference as an error
        } else {
            std::cout << "    VULNERABILITY NOT CONFIRMED <<<" << std::endl;
            std::cout << "    Generated path matches the expected correct BIP-44 path." << std::endl;
             std::cout << "    The vulnerability may be fixed or the test setup is incorrect." << std::endl;
        }
    } else {
        std::cout << "\n>>> Proof Verdict: FAILED <<<" << std::endl;
        std::cout << "   build_bip44_path returned an error status (" << status << ")." << std::endl;
        std::cout << "   Cannot perform path comparison." << std::endl;
        errors++; // Count function failure as an error
    }

    // --- Final Test Summary ---
    std::cout << "\n===============================================" << std::endl;
    if (errors > 0) {
         std::cout << "=== TEST RESULT: FAILED (" << errors << " mismatches/errors found) ===" << std::endl;
         std::cout << "                 (Indicates vulnerability is likely PRESENT)" << std::endl;
    } else {
         std::cout << "=== TEST RESULT: PASSED (No Mismatches Found) ===" << std::endl;
         std::cout << "                 (Indicates vulnerability is likely ABSENT or fixed)" << std::endl;
    }
    std::cout << "===============================================" << std::endl;

    // Return 0 if path was correct, non-zero if errors/mismatches found
    return errors;
}