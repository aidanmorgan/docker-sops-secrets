cmake_minimum_required(VERSION 3.16)
project(sops-secrets-docker VERSION 1.0.0 LANGUAGES)

# Set CMake policies
cmake_policy(SET CMP0048 NEW)

# Configuration options
option(RUN_INTEGRATION_TESTS "Run integration tests" ON)

# Integration test configuration
set(INTEGRATION_TEST_DIR "${CMAKE_SOURCE_DIR}/tests/integration-local" CACHE STRING "Integration test directory")
set(INTEGRATION_TEST_RESULTS_DIR "${CMAKE_BINARY_DIR}/test-results" CACHE STRING "Integration test results directory")
set(INTEGRATION_TEST_TIMEOUT "600" CACHE STRING "Integration test timeout in seconds")

# Build directories
set(BUILD_DIR "${CMAKE_BINARY_DIR}")

# Create build directories
file(MAKE_DIRECTORY ${INTEGRATION_TEST_RESULTS_DIR})

# Define binary output paths
set(LOCAL_BINARY_PATH "${CMAKE_SOURCE_DIR}/target/release/sops-secrets-server-local")
set(SECURE_BINARY_PATH "${CMAKE_SOURCE_DIR}/target/release/sops-secrets-server")
set(CLI_BINARY_PATH "${CMAKE_SOURCE_DIR}/target/release/sops-secrets-cli")
set(EXPORTER_BINARY_PATH "${CMAKE_SOURCE_DIR}/target/release/sops-secrets-exporter")

# Find all Rust source files for dependency tracking to try and improve time to run integration tests
file(GLOB_RECURSE RUST_SOURCES 
    "${CMAKE_SOURCE_DIR}/src/*.rs"
    "${CMAKE_SOURCE_DIR}/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/Cargo.lock"
)

# Build local binary for testing with proper dependencies
add_custom_command(
    OUTPUT ${LOCAL_BINARY_PATH}
    COMMAND ${CMAKE_COMMAND} -E echo "🔨 Building local server binary..."
    COMMAND cargo build --release --features insecure_mode
    COMMAND ${CMAKE_COMMAND} -E echo "Local server binary built successfully"
    DEPENDS ${RUST_SOURCES}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building local server binary for testing"
    VERBATIM
)

# Build CLI binary for testing with proper dependencies
add_custom_command(
    OUTPUT ${CLI_BINARY_PATH}
    COMMAND ${CMAKE_COMMAND} -E echo "🔨 Building CLI binary..."
    COMMAND cargo build --release --bin sops-secrets-cli
    COMMAND ${CMAKE_COMMAND} -E echo "CLI binary built successfully"
    DEPENDS ${RUST_SOURCES}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building CLI binary for testing"
    VERBATIM
)

# Build exporter binary for testing with proper dependencies
add_custom_command(
    OUTPUT ${EXPORTER_BINARY_PATH}
    COMMAND ${CMAKE_COMMAND} -E echo "🔨 Building exporter binary..."
    COMMAND cargo build --release --bin sops-secrets-exporter
    COMMAND ${CMAKE_COMMAND} -E echo "Exporter binary built successfully"
    DEPENDS ${RUST_SOURCES}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building exporter binary for testing"
    VERBATIM
)

# Build secure server binary (no insecure_mode feature)
add_custom_command(
    OUTPUT ${SECURE_BINARY_PATH}
    COMMAND ${CMAKE_COMMAND} -E echo "🔒 Building secure server binary..."
    COMMAND cargo build --release --bin sops-secrets-server --target-dir target && cp target/release/sops-secrets-server ${SECURE_BINARY_PATH}
    COMMAND ${CMAKE_COMMAND} -E echo "Secure server binary built successfully"
    DEPENDS ${RUST_SOURCES}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building secure server binary"
    VERBATIM
)

# Create targets that depend on the custom commands
add_custom_target(build-local-binary DEPENDS ${LOCAL_BINARY_PATH})
add_custom_target(build-cli-binary DEPENDS ${CLI_BINARY_PATH})
add_custom_target(build-exporter-binary DEPENDS ${EXPORTER_BINARY_PATH})
add_custom_target(build-secure-binary DEPENDS ${SECURE_BINARY_PATH})

# Integration test targets (local binary-based)
if(RUN_INTEGRATION_TESTS)
    # Run integration tests
    add_custom_target(integration-tests
        COMMAND ${CMAKE_COMMAND} -E echo "🚀 Starting integration tests..."
        COMMAND ${CMAKE_COMMAND} -E echo "Test results will be saved to: ${INTEGRATION_TEST_RESULTS_DIR}"
        COMMAND ${CMAKE_COMMAND} -E echo "Server logs will be saved to: ${INTEGRATION_TEST_DIR}/results"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INTEGRATION_TEST_RESULTS_DIR}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INTEGRATION_TEST_DIR}/results
        COMMAND ${CMAKE_COMMAND} -E echo "Installing test dependencies..."
        COMMAND uv sync --project ${INTEGRATION_TEST_DIR}
        COMMAND ${CMAKE_COMMAND} -E echo "🧪 Running pytest integration tests..."
        COMMAND uv run --project ${INTEGRATION_TEST_DIR} pytest ${INTEGRATION_TEST_DIR} -v -s --tb=short | tee ${INTEGRATION_TEST_RESULTS_DIR}/test_output.log
        COMMAND ${CMAKE_COMMAND} -E echo "📋 Appending server logs to test output..."
        COMMAND find ${INTEGRATION_TEST_DIR} -name "server.log" -exec echo "=== Server Logs ===" \; -exec cat {} \; >> ${INTEGRATION_TEST_RESULTS_DIR}/test_output.log || ${CMAKE_COMMAND} -E echo "No server logs found"
        COMMAND ${CMAKE_COMMAND} -E echo "📋 Server logs and test artifacts saved to: ${INTEGRATION_TEST_DIR}/results"
        COMMAND ${CMAKE_COMMAND} -E echo "Integration tests completed"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running integration tests"
        VERBATIM
    )
    
    # Run integration tests with detailed output
    add_custom_target(integration-tests-verbose
        COMMAND ${CMAKE_COMMAND} -E echo "🚀 Starting integration tests (verbose mode)..."
        COMMAND ${CMAKE_COMMAND} -E echo "Test results will be saved to: ${INTEGRATION_TEST_RESULTS_DIR}"
        COMMAND ${CMAKE_COMMAND} -E echo "Server logs will be saved to: ${INTEGRATION_TEST_DIR}/results"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INTEGRATION_TEST_RESULTS_DIR}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INTEGRATION_TEST_DIR}/results
        COMMAND ${CMAKE_COMMAND} -E echo "Installing test dependencies..."
        COMMAND uv sync --project ${INTEGRATION_TEST_DIR}
        COMMAND ${CMAKE_COMMAND} -E echo "🧪 Running pytest integration tests (verbose)..."
        COMMAND uv run --project ${INTEGRATION_TEST_DIR} pytest ${INTEGRATION_TEST_DIR} -v -s --tb=short | tee ${INTEGRATION_TEST_RESULTS_DIR}/test_output.log
        COMMAND ${CMAKE_COMMAND} -E echo "📋 Appending server logs to test output..."
        COMMAND find ${INTEGRATION_TEST_DIR} -name "server.log" -exec echo "=== Server Logs ===" \; -exec cat {} \; >> ${INTEGRATION_TEST_RESULTS_DIR}/test_output.log || ${CMAKE_COMMAND} -E echo "No server logs found"
        COMMAND ${CMAKE_COMMAND} -E echo "📋 Server logs and test artifacts saved to: ${INTEGRATION_TEST_DIR}/results"
        COMMAND ${CMAKE_COMMAND} -E echo "Integration tests completed"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running integration tests with detailed output"
        VERBATIM
    )
    
    # Clean integration test environment
    add_custom_target(integration-tests-clean
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning integration test environment..."
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning Python virtual environments..."
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${INTEGRATION_TEST_DIR}/.venv || true
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/../clients/python/.venv || true
        COMMAND ${CMAKE_COMMAND} -E echo "Integration test environment cleaned"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Cleaning integration test environment"
        VERBATIM
    )
    
    # Show integration test results
    add_custom_target(integration-tests-results
        COMMAND ${CMAKE_COMMAND} -E echo "📊 Integration Test Results"
        COMMAND ${CMAKE_COMMAND} -E echo "=========================="
        COMMAND ${CMAKE_COMMAND} -E echo "Results directory: ${INTEGRATION_TEST_RESULTS_DIR}"
        COMMAND ${CMAKE_COMMAND} -E ls -la ${INTEGRATION_TEST_RESULTS_DIR} || ${CMAKE_COMMAND} -E echo "No test results found"
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMAND ${CMAKE_COMMAND} -E echo "📄 Test Report (if available):"
        COMMAND cat ${INTEGRATION_TEST_RESULTS_DIR}/integration_test_report.json || ${CMAKE_COMMAND} -E echo "No test report found"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Showing integration test results"
        VERBATIM
    )
    
    # Set dependencies
    add_dependencies(integration-tests build-local-binary)
    add_dependencies(integration-tests-verbose build-local-binary)
    add_dependencies(integration-tests-results integration-tests)
endif()

# Print configuration summary
message(STATUS "Configuration:")
message(STATUS "  Integration tests: ${RUN_INTEGRATION_TESTS}")
message(STATUS "  Test results directory: ${INTEGRATION_TEST_RESULTS_DIR}")

# Available targets summary
message(STATUS "")
message(STATUS "Available targets:")
message(STATUS "  build-local-binary          - Build local server binary")
message(STATUS "  build-secure-binary         - Build secure server binary")
message(STATUS "  build-cli-binary            - Build CLI binary for testing")
message(STATUS "  build-exporter-binary       - Build exporter binary for testing")

if(RUN_INTEGRATION_TESTS)
    message(STATUS "")
    message(STATUS "Available Integration Test targets:")
    message(STATUS "  integration-tests              - Run integration tests")
    message(STATUS "  integration-tests-verbose       - Run integration tests with detailed output")
    message(STATUS "  integration-tests-clean         - Clean integration test environment")
    message(STATUS "  integration-tests-results       - Show integration test results")
endif()

 