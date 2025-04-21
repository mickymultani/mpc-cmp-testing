/**
 * Test Name: test_bip32_checks
 *
 * Objective:
 *   Demonstrate that the Fireblocks MPC library's elliptic curve
 *   algebra functions (specifically add_scalars and add_points/generator_mul_data)
 *   do NOT implement the BIP-32 standard's mandatory validity checks for
 *   derived keys.
 *
 * Vulnerability Tested:
 *   Missing check for derived private key == 0.
 *   Missing check for derived public key == Point-at-Infinity.
 *
 * Expected Outcome:
 *   The test calculates inputs that mathematically result in a zero private key
 *   and a point-at-infinity public key. It calls the library functions and expects
 *   them to return SUCCESS status codes, despite the invalid results. The output
 *   will explicitly show the zero private key and the infinity public key bytes
 *   alongside the success status, proving the checks are missing.
 *
 * Impact:
 *   Generation of invalid, unspendable keys, leading to potential permanent
 *   loss of funds if such keys are used in production wallets. Non-compliance
 *   with the BIP-32 standard.
 */

#include <iostream>     // For std::cout, std::cerr
#include <vector>       // Potentially useful, though not strictly needed here
#include <cstdint>      // For uint8_t, uint32_t
#include <cstring>      // For memcmp
#include <cassert>      // For assert (optional, for internal checks)
#include <iomanip>      // For std::hex, std::setw, std::setfill, std::showbase

// --- OpenSSL Includes ---
// Required for BIGNUM operations to calculate the specific tweak value.
#include <openssl/bn.h>
// The following OpenSSL includes might be implicitly included by the Fireblocks headers,
// but keeping them doesn't hurt.
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// --- FIX: Define COSIGNER_EXPORT as empty before including library headers ---
// This prevents errors related to this macro not being defined when compiling tests.
#define COSIGNER_EXPORT

// --- Fireblocks mpc-lib Includes ---
// Corrected Include paths based on 'tree include' output
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h" // Provides elliptic_curve256_algebra_ctx_t and factory functions
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h" // Provides the concrete implementation details (needed for factory function)

// --- Type Definitions ---
// Define fixed-size arrays for keys/scalars for clarity.
// These sizes should match the underlying curve (secp256k1).
const uint32_t PRIVATE_KEY_SIZE = 32;
const uint32_t COMPRESSED_PUBLIC_KEY_SIZE = 33;
typedef uint8_t PrivKey[PRIVATE_KEY_SIZE];
typedef uint8_t PubKey[COMPRESSED_PUBLIC_KEY_SIZE];
typedef uint8_t Scalar[PRIVATE_KEY_SIZE]; // A scalar (like the tweak) is 32 bytes

// --- Constants ---
// Define the specific byte marker expected for the point-at-infinity (compressed)
// OpenSSL's EC_POINT_point2oct with POINT_CONVERSION_COMPRESSED uses 0x00.
const uint8_t POINT_AT_INFINITY_MARKER = 0x00;

// --- Helper Functions ---

// Prints a byte array in hexadecimal format.
void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << " 0x";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl; // Switch back to decimal mode
}

// Checks if a byte array contains only zero bytes.
bool is_zero(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (data[i] != 0) return false;
    }
    return true;
}

// Checks if the provided data represents the compressed point-at-infinity.
bool is_infinity_representation(const uint8_t* data, size_t len) {
     if (len == 0) return false; // Check for empty data
     // The standard compressed representation of infinity is just 0x00.
     return data[0] == POINT_AT_INFINITY_MARKER;
     // The rest of the buffer might be zero-padded by some implementations,
     // but the marker byte is the definitive check.
}

// --- Cleanup Function ---
// Consolidates resource cleanup to avoid goto issues.
void cleanup_resources(elliptic_curve256_algebra_ctx_t* ctx, BN_CTX* bn_ctx, BIGNUM* bn_k_par, BIGNUM* bn_n, BIGNUM* bn_t) {
    std::cout << "\n[Cleanup] Releasing resources..." << std::endl;
    if (bn_ctx) BN_CTX_free(bn_ctx);
    if (bn_k_par) BN_free(bn_k_par);
    if (bn_n) BN_free(bn_n);
    if (bn_t) BN_free(bn_t);
    if (ctx) ctx->release(ctx); // Use the release function pointer from the context
    std::cout << "Cleanup complete." << std::endl;
}


// --- Main Test Logic ---
int main() {
    std::cout << "===============================================" << std::endl;
    std::cout << "=== Test: BIP-32 Missing Validity Checks ====" << std::endl;
    std::cout << "===============================================" << std::endl;
    int final_error_code = 0; // Track overall test success/failure

    // Declare ALL BIGNUM and ctx variables here at the top level of main
    elliptic_curve256_algebra_ctx_t* ctx = nullptr;
    BN_CTX* bn_ctx = nullptr;
    BIGNUM* bn_k_par = nullptr;
    BIGNUM* bn_n = nullptr;
    BIGNUM* bn_t = nullptr;
    const BIGNUM* order_internal_ptr = nullptr; // Pointer to internal BIGNUM order


    // --- Step 1: Initialize Context and BIGNUMs ---
    std::cout << "\n[Step 1] Initializing context and OpenSSL BIGNUMs..." << std::endl;
    ctx = elliptic_curve256_new_secp256k1_algebra();
    if (!ctx) {
        std::cerr << "FATAL ERROR: elliptic_curve256_new_secp256k1_algebra() returned NULL." << std::endl;
        return 1; // Cannot run test
    }
    bn_ctx = BN_CTX_new();
    bn_k_par = BN_new();
    bn_n = BN_new();
    bn_t = BN_new();
    if (!bn_ctx || !bn_k_par || !bn_n || !bn_t) {
         std::cerr << "FATAL ERROR: Failed to allocate OpenSSL BIGNUM resources." << std::endl;
         // Cleanup what was allocated before returning
         cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
         return 1;
    }
    std::cout << "Context and BIGNUMs created successfully." << std::endl;

    // --- Step 2: Define Test Inputs ---
    std::cout << "\n[Step 2] Defining test inputs..." << std::endl;
    PrivKey k_par = { // Parent Private Key (k_par = 1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    PubKey K_par;  // To store the corresponding parent public key
    Scalar tweak;  // To store the calculated tweak t = (n - k_par) mod n
    print_hex("Input Parent Private Key (k_par):", k_par, PRIVATE_KEY_SIZE);


    // --- Step 3: Calculate Corresponding Parent Public Key ---
    std::cout << "\n[Step 3] Calculating parent public key K_par = G * k_par..." << std::endl;
    elliptic_curve_algebra_status status;
    status = ctx->generator_mul(ctx, &K_par, &k_par);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        std::cerr << "FATAL ERROR: Failed to calculate parent public key K_par via ctx->generator_mul. Status: " << status << std::endl;
        final_error_code = 1;
        cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
        return final_error_code;
    }
    print_hex("Calculated Parent Public Key (K_par): ", K_par, COMPRESSED_PUBLIC_KEY_SIZE);


    // --- Step 4: Obtain Curve Order and Calculate Inverse Tweak ---
    std::cout << "\n[Step 4] Calculating special tweak t = (n - k_par) mod n..." << std::endl;
    order_internal_ptr = ctx->order_internal(ctx);
    if (!order_internal_ptr) {
        const uint8_t* order_bytes = ctx->order(ctx);
        if (!order_bytes || !BN_bin2bn(order_bytes, PRIVATE_KEY_SIZE, bn_n)) {
            std::cerr << "FATAL ERROR: Failed to get curve order via ctx->order_internal() or ctx->order()." << std::endl;
            final_error_code = 1;
            cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
            return final_error_code;
        }
        std::cout << "INFO: Used ctx->order() for curve order." << std::endl;
    } else {
        if (!BN_copy(bn_n, order_internal_ptr)) {
             std::cerr << "FATAL ERROR: Failed to copy curve order BIGNUM via BN_copy." << std::endl;
             final_error_code = 1;
             cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
             return final_error_code;
        }
         std::cout << "INFO: Used ctx->order_internal() for curve order." << std::endl;
    }
    uint8_t order_print_buf[PRIVATE_KEY_SIZE];
    BN_bn2binpad(bn_n, order_print_buf, PRIVATE_KEY_SIZE);
    print_hex("Curve Order (n):                 ", order_print_buf, PRIVATE_KEY_SIZE);

    if (!BN_bin2bn(k_par, PRIVATE_KEY_SIZE, bn_k_par)) {
        std::cerr << "FATAL ERROR: Failed to convert k_par to BIGNUM." << std::endl;
        final_error_code = 1;
        cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
        return final_error_code;
    }
    if (!BN_mod_sub(bn_t, bn_n, bn_k_par, bn_n, bn_ctx)) {
       std::cerr << "FATAL ERROR: Failed to calculate bn_t = (n - k_par) mod n." << std::endl;
       final_error_code = 1;
       cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
       return final_error_code;
    }
    if (BN_bn2binpad(bn_t, tweak, PRIVATE_KEY_SIZE) <= 0) {
       std::cerr << "FATAL ERROR: Failed to convert calculated tweak bn_t to bytes." << std::endl;
       final_error_code = 1;
       cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);
       return final_error_code;
    }
    print_hex("Calculated Inverse Tweak (t):    ", tweak, PRIVATE_KEY_SIZE);


    // --- Step 5: Test Private Key Derivation ---
    // Use a scope block {} to limit the lifetime of variables declared inside
    {
        std::cout << "\n------------------------------------------------" << std::endl;
        std::cout << "--- Proof Attempt 1: Check derived_k == 0 ---" << std::endl;
        std::cout << "------------------------------------------------" << std::endl;
        std::cout << "Calling ctx->add_scalars with k_par and calculated tweak t..." << std::endl;

        PrivKey derived_k = {0xff}; // Initialize to non-zero
        elliptic_curve_algebra_status add_scalar_status;
        add_scalar_status = ctx->add_scalars(ctx, &derived_k, k_par, PRIVATE_KEY_SIZE, tweak, PRIVATE_KEY_SIZE);

        std::cout << " -> add_scalars status code returned: " << add_scalar_status << " (Expected for bug: " << ELLIPTIC_CURVE_ALGEBRA_SUCCESS << ")" << std::endl;
        print_hex(" -> Resulting derived_k:", derived_k, PRIVATE_KEY_SIZE);
        bool derived_k_is_zero = is_zero(derived_k, PRIVATE_KEY_SIZE);
        std::cout << " -> Is derived_k all zeros? " << (derived_k_is_zero ? "YES" : "NO") << std::endl;

        if (add_scalar_status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS && derived_k_is_zero) {
            std::cout << "\n>>> Proof 1 Verdict: VULNERABILITY CONFIRMED <<<" << std::endl;
            std::cout << "   add_scalars returned SUCCESS despite producing a ZERO private key." << std::endl;
            std::cout << "   This violates BIP-32 validity checks." << std::endl;
        } else {
            std::cout << "\n>>> Proof 1 Verdict: FAILED <<<" << std::endl;
            if (add_scalar_status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
                 std::cout << "   Reason: add_scalars returned an error status (" << add_scalar_status << ")." << std::endl;
            } else { // derived_k_is_zero == false
                 std::cout << "   Reason: add_scalars returned SUCCESS but derived key was NOT zero." << std::endl;
            }
            std::cout << "   Vulnerability for zero private key check not confirmed by this test." << std::endl;
            final_error_code = 1; // Mark test as failed overall
        }
    } // End of scope for derived_k


    // --- Step 6: Test Public Key Derivation ---
    // Use a scope block {} to limit the lifetime of variables declared inside
    {
        std::cout << "\n---------------------------------------------------" << std::endl;
        std::cout << "--- Proof Attempt 2: Check derived_K == Infinity ---" << std::endl;
        std::cout << "---------------------------------------------------" << std::endl;
        PubKey T_point; // Intermediate point: T = G * t
        PubKey derived_K = {0xff}; // Initialize to non-infinity
        elliptic_curve_algebra_status gen_mul_status;
        elliptic_curve_algebra_status add_points_status;

        std::cout << "Calling ctx->generator_mul_data with tweak t..." << std::endl;
        gen_mul_status = ctx->generator_mul_data(ctx, tweak, PRIVATE_KEY_SIZE, &T_point);

        if (gen_mul_status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            std::cerr << "ERROR during test: Failed to calculate intermediate T_point = G*t via ctx->generator_mul_data. Status: " << gen_mul_status << std::endl;
            final_error_code = 1; // Mark test as failed
             std::cout << "\n>>> Proof 2 Verdict: FAILED <<<" << std::endl;
             std::cout << "   Reason: generator_mul_data failed before add_points could be tested." << std::endl;
        } else {
            print_hex(" -> Intermediate T_point (G*t):", T_point, COMPRESSED_PUBLIC_KEY_SIZE);
            std::cout << "Calling ctx->add_points with T_point and K_par..." << std::endl;
            add_points_status = ctx->add_points(ctx, &derived_K, &T_point, &K_par);

            std::cout << " -> add_points status code returned: " << add_points_status << " (Expected for bug: " << ELLIPTIC_CURVE_ALGEBRA_SUCCESS << ")" << std::endl;
            print_hex(" -> Resulting derived_K:", derived_K, COMPRESSED_PUBLIC_KEY_SIZE);
            bool derived_K_is_infinity = is_infinity_representation(derived_K, COMPRESSED_PUBLIC_KEY_SIZE);
            std::cout << " -> Does derived_K represent Point-at-Infinity? " << (derived_K_is_infinity ? "YES" : "NO") << std::endl;

            if (add_points_status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS && derived_K_is_infinity) {
                 std::cout << "\n>>> Proof 2 Verdict: VULNERABILITY CONFIRMED <<<" << std::endl;
                 std::cout << "   add_points returned SUCCESS despite producing the Point-at-Infinity." << std::endl;
                 std::cout << "   This violates BIP-32 validity checks." << std::endl;
            } else {
                 std::cout << "\n>>> Proof 2 Verdict: FAILED <<<" << std::endl;
                 if (add_points_status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
                      std::cout << "   Reason: add_points returned an error status (" << add_points_status << ")." << std::endl;
                 } else { // derived_K_is_infinity == false
                       std::cout << "   Reason: add_points returned SUCCESS but derived key did not represent Point-at-Infinity." << std::endl;
                 }
                 std::cout << "   Vulnerability for infinity public key check not confirmed by this test." << std::endl;
                 final_error_code = 1; // Mark test as failed overall
            }
        }
    } // End of scope for derived_K


    // --- Final Cleanup ---
    // Cleanup resources allocated at the beginning
    cleanup_resources(ctx, bn_ctx, bn_k_par, bn_n, bn_t);


    // --- Final Test Summary ---
    std::cout << "\n===============================================" << std::endl;
    if (final_error_code == 0) {
        std::cout << "=== TEST RESULT: PASSED (Vulnerabilities Confirmed) ===" << std::endl;
    } else {
        std::cout << "=== TEST RESULT: FAILED (" << final_error_code << " proof(s) failed or errors occurred) ===" << std::endl;
    }
    std::cout << "===============================================" << std::endl;

    // Return 0 if proofs passed (vulnerabilities confirmed), non-zero otherwise
    return final_error_code;
}