# Set minimum CMake version
cmake_minimum_required(VERSION 3.10)

# Define project name and language
project(FireblocksMPCTests CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find Required Libraries ---

# Find OpenSSL (headers and libraries)
find_package(OpenSSL REQUIRED)

# --- Define Locations for the Fireblocks MPC Library ---

# Base directory containing the mpc-lib public 'include' directory
# Assumes mpc-lib is a subdirectory of the current project (mpc-test)
set(MPC_LIB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc-lib/include)

# Base directory where mpc-lib was built
set(MPC_LIB_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mpc-lib/build)

# Specific directory containing the compiled shared library (libcosigner.so)
set(MPC_LIB_LIBRARY_PATH ${MPC_LIB_BUILD_DIR}/src/common)

# --- Sanity Checks ---

# Check if the include directory exists
if(NOT EXISTS ${MPC_LIB_INCLUDE_DIR})
     message(FATAL_ERROR "MPC Library include directory not found: ${MPC_LIB_INCLUDE_DIR}. Please ensure mpc-lib is present and check this path.")
endif()

# Check if the library file actually exists at the specified path.
if(NOT EXISTS ${MPC_LIB_LIBRARY_PATH}/libcosigner.so)
     message(FATAL_ERROR "MPC Library file not found: ${MPC_LIB_LIBRARY_PATH}/libcosigner.so. Please ensure mpc-lib was built successfully and check this path.")
endif()

# --- Define the Test Executable Programs ---
# For each executable, we define its source file, where to find includes,
# where to find libraries to link against, and which libraries to link.

# Test 1: BIP-32 Checks
add_executable(test_bip32_checks test_bip32_checks.cpp)
# Specify include path specifically for this target (points to mpc-lib/include)
target_include_directories(test_bip32_checks PRIVATE ${MPC_LIB_INCLUDE_DIR})
# Specify library path specifically for this target
target_link_directories(test_bip32_checks PRIVATE ${MPC_LIB_LIBRARY_PATH})
# Link against the 'cosigner' library and OpenSSL libraries
target_link_libraries(test_bip32_checks PRIVATE cosigner ${OPENSSL_LIBRARIES})

# Test 2: BIP-44 Paths
add_executable(test_bip44_paths test_bip44_paths.cpp)
# Specify include path specifically for this target
target_include_directories(test_bip44_paths PRIVATE ${MPC_LIB_INCLUDE_DIR})
# Specify library path specifically for this target
target_link_directories(test_bip44_paths PRIVATE ${MPC_LIB_LIBRARY_PATH})
# Link against the 'cosigner' library and OpenSSL libraries
target_link_libraries(test_bip44_paths PRIVATE cosigner ${OPENSSL_LIBRARIES})

# Test 3: Null Context Crash
add_executable(test_null_context test_null_context.cpp)
# Specify include path specifically for this target
target_include_directories(test_null_context PRIVATE ${MPC_LIB_INCLUDE_DIR})
# Specify library path specifically for this target
target_link_directories(test_null_context PRIVATE ${MPC_LIB_LIBRARY_PATH})
# Link against the 'cosigner' library and OpenSSL libraries
target_link_libraries(test_null_context PRIVATE cosigner ${OPENSSL_LIBRARIES})


# --- Runtime Path (RPATH) Configuration for Linux/WSL ---
# This embeds the path to the shared library into the executables,
# making it easier to run them directly from the build directory.

# Get the absolute path to the library directory for robustness
get_filename_component(MPC_LIB_LIBRARY_ABSOLUTE_PATH ${MPC_LIB_LIBRARY_PATH} ABSOLUTE)

# Configure RPATH settings
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH ${MPC_LIB_LIBRARY_ABSOLUTE_PATH})
set(CMAKE_BUILD_RPATH ${MPC_LIB_LIBRARY_ABSOLUTE_PATH})