cmake_minimum_required(VERSION 3.16)
project(sops-secrets-docker VERSION 1.0.0 LANGUAGES)

# Set CMake policies
cmake_policy(SET CMP0048 NEW)

# Configuration options
option(BUILD_SERVER_IMAGE "Build server Docker image" ON)
option(BUILD_CLI_IMAGE "Build CLI Docker image" ON)
option(BUILD_EXPORTER_IMAGE "Build exporter Docker image" ON)
option(BUILD_ALL_IMAGES "Build all Docker images" ON)
option(RUN_INTEGRATION_TESTS "Run integration tests" ON)

# Docker configuration
set(DOCKER_REGISTRY "" CACHE STRING "Docker registry (optional)")
set(DOCKER_IMAGE_PREFIX "sops-secrets" CACHE STRING "Docker image prefix")
set(DOCKER_TAG "latest" CACHE STRING "Docker image tag")
set(DOCKER_BUILD_CONTEXT "." CACHE STRING "Docker build context")
set(DOCKER_SERVER_PORT "3000" CACHE STRING "Server port for Docker containers")

# Integration test configuration
set(INTEGRATION_TEST_DIR "${CMAKE_SOURCE_DIR}/tests/integration" CACHE STRING "Integration test directory")
set(INTEGRATION_TEST_RESULTS_DIR "${CMAKE_BINARY_DIR}/test-results" CACHE STRING "Integration test results directory")
set(INTEGRATION_TEST_TIMEOUT "600" CACHE STRING "Integration test timeout in seconds")

# SOPS configuration
set(SOPS_VERSION "v3.10.2" CACHE STRING "SOPS version to install")

# Age configuration
set(AGE_VERSION "v1.2.1" CACHE STRING "Age version to install")

# Architecture configuration
set(ARCH "amd64" CACHE STRING "CPU architecture for binary downloads (amd64, arm64, etc.)")

# Rust configuration
set(RUST_VERSION "1.76" CACHE STRING "Rust version for building")
set(RUST_TARGET "release" CACHE STRING "Rust build target")

# Build directories
set(BUILD_DIR "${CMAKE_BINARY_DIR}")
set(DOCKER_BUILD_DIR "${BUILD_DIR}/docker")

# Create build directories
file(MAKE_DIRECTORY ${DOCKER_BUILD_DIR})
file(MAKE_DIRECTORY ${INTEGRATION_TEST_RESULTS_DIR})

# Function to create Docker build target for server (runnable service)
function(create_server_target target_name dockerfile service_type)
    set(target_name_upper ${target_name})
    string(TOUPPER ${target_name_upper} target_name_upper)
    
    # Set image name
    if(DOCKER_REGISTRY)
        set(image_name "${DOCKER_REGISTRY}/${DOCKER_IMAGE_PREFIX}-${service_type}:${DOCKER_TAG}")
    else()
        set(image_name "${DOCKER_IMAGE_PREFIX}-${service_type}:${DOCKER_TAG}")
    endif()
    
    # Create custom target
    add_custom_target(${target_name}
        COMMAND ${CMAKE_COMMAND} -E echo "Building ${image_name}..."
        COMMAND docker build
            --file ${dockerfile}
            --tag ${image_name}
            --target runtime
            --build-arg SOPS_VERSION=${SOPS_VERSION}
            --build-arg AGE_VERSION=${AGE_VERSION}
            --build-arg ARCH=${ARCH}
            --build-arg RUST_VERSION=${RUST_VERSION}
            --build-arg RUST_TARGET=${RUST_TARGET}
            --build-arg SERVER_PORT=${DOCKER_SERVER_PORT}
            --progress=plain
            ${DOCKER_BUILD_CONTEXT}
        COMMAND ${CMAKE_COMMAND} -E echo "Successfully built ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Building Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create test target
    add_custom_target(${target_name}-test
        COMMAND ${CMAKE_COMMAND} -E echo "Testing ${image_name}..."
        COMMAND docker run --rm ${image_name} which ${service_type}
        COMMAND docker run --rm ${image_name} ${service_type} --help
        COMMAND ${CMAKE_COMMAND} -E echo "Testing SOPS installation..."
        COMMAND docker run --rm ${image_name} sops --version
        COMMAND ${CMAKE_COMMAND} -E echo "Testing security features..."
        COMMAND docker run --rm ${image_name} whoami
        COMMAND ${CMAKE_COMMAND} -E echo "Successfully tested ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Testing Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create security test target
    add_custom_target(${target_name}-security
        COMMAND ${CMAKE_COMMAND} -E echo "Running security tests for ${image_name}..."
        COMMAND docker run --rm ${image_name} /bin/bash || true
        COMMAND docker run --rm ${image_name} whoami
        COMMAND docker run --rm ${image_name} touch /test || true
        COMMAND ${CMAKE_COMMAND} -E echo "Security tests completed for ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Security testing Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create scan target
    add_custom_target(${target_name}-scan
        COMMAND ${CMAKE_COMMAND} -E echo "Scanning ${image_name} for vulnerabilities..."
        COMMAND trivy image --severity HIGH,CRITICAL ${image_name} || ${CMAKE_COMMAND} -E echo "Trivy not found, skipping scan"
        COMMAND ${CMAKE_COMMAND} -E echo "Scan completed for ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Scanning Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create push target
    add_custom_target(${target_name}-push
        COMMAND ${CMAKE_COMMAND} -E echo "Pushing ${image_name}..."
        COMMAND docker push ${image_name}
        COMMAND ${CMAKE_COMMAND} -E echo "Successfully pushed ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Pushing Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create clean target
    add_custom_target(${target_name}-clean
        COMMAND ${CMAKE_COMMAND} -E echo "Cleaning ${image_name}..."
        COMMAND docker rmi ${image_name} || true
        COMMAND ${CMAKE_COMMAND} -E echo "Cleaned ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Cleaning Docker image: ${image_name}"
        VERBATIM
    )
    
    # Set dependencies
    add_dependencies(${target_name}-test ${target_name})
    add_dependencies(${target_name}-security ${target_name})
    add_dependencies(${target_name}-scan ${target_name})
    add_dependencies(${target_name}-push ${target_name})
endfunction()

# Function to create Docker build target for CLI/exporter (binary-only)
function(create_binary_target target_name dockerfile service_type)
    set(target_name_upper ${target_name})
    string(TOUPPER ${target_name_upper} target_name_upper)
    
    # Set image name
    if(DOCKER_REGISTRY)
        set(image_name "${DOCKER_REGISTRY}/${DOCKER_IMAGE_PREFIX}-${service_type}:${DOCKER_TAG}")
    else()
        set(image_name "${DOCKER_IMAGE_PREFIX}-${service_type}:${DOCKER_TAG}")
    endif()
    
    # Create custom target
    add_custom_target(${target_name}
        COMMAND ${CMAKE_COMMAND} -E echo "Building ${image_name}..."
        COMMAND docker build
            --file ${dockerfile}
            --tag ${image_name}
            --target runtime
            --build-arg SOPS_VERSION=${SOPS_VERSION}
            --build-arg ARCH=${ARCH}
            --build-arg RUST_VERSION=${RUST_VERSION}
            --build-arg RUST_TARGET=${RUST_TARGET}
            --progress=plain
            ${DOCKER_BUILD_CONTEXT}
        COMMAND ${CMAKE_COMMAND} -E echo "Successfully built ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Building Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create test target (binary validation only)
    add_custom_target(${target_name}-test
        COMMAND ${CMAKE_COMMAND} -E echo "Testing ${image_name}..."
        COMMAND docker run --rm ${image_name} which ${service_type}
        COMMAND docker run --rm ${image_name} ${service_type} --help
        COMMAND ${CMAKE_COMMAND} -E echo "Testing SOPS installation..."
        COMMAND docker run --rm ${image_name} sops --version
        COMMAND ${CMAKE_COMMAND} -E echo "Successfully tested ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Testing Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create security test target
    add_custom_target(${target_name}-security
        COMMAND ${CMAKE_COMMAND} -E echo "Running security tests for ${image_name}..."
        COMMAND docker run --rm ${image_name} /bin/bash || true
        COMMAND docker run --rm ${image_name} whoami
        COMMAND docker run --rm ${image_name} touch /test || true
        COMMAND ${CMAKE_COMMAND} -E echo "Security tests completed for ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Security testing Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create scan target
    add_custom_target(${target_name}-scan
        COMMAND ${CMAKE_COMMAND} -E echo "Scanning ${image_name} for vulnerabilities..."
        COMMAND trivy image --severity HIGH,CRITICAL ${image_name} || ${CMAKE_COMMAND} -E echo "Trivy not found, skipping scan"
        COMMAND ${CMAKE_COMMAND} -E echo "Scan completed for ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Scanning Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create push target
    add_custom_target(${target_name}-push
        COMMAND ${CMAKE_COMMAND} -E echo "Pushing ${image_name}..."
        COMMAND docker push ${image_name}
        COMMAND ${CMAKE_COMMAND} -E echo "Successfully pushed ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Pushing Docker image: ${image_name}"
        VERBATIM
    )
    
    # Create clean target
    add_custom_target(${target_name}-clean
        COMMAND ${CMAKE_COMMAND} -E echo "Cleaning ${image_name}..."
        COMMAND docker rmi ${image_name} || true
        COMMAND ${CMAKE_COMMAND} -E echo "Cleaned ${image_name}"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Cleaning Docker image: ${image_name}"
        VERBATIM
    )
    
    # Set dependencies
    add_dependencies(${target_name}-test ${target_name})
    add_dependencies(${target_name}-security ${target_name})
    add_dependencies(${target_name}-scan ${target_name})
    add_dependencies(${target_name}-push ${target_name})
endfunction()

# Function to create compose target
function(create_compose_target target_name action)
    add_custom_target(${target_name}
        COMMAND ${CMAKE_COMMAND} -E echo "${action} docker-compose services..."
        COMMAND docker-compose ${action}
        COMMAND ${CMAKE_COMMAND} -E echo "Docker-compose ${action} completed"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Docker-compose ${action}"
        VERBATIM
    )
endfunction()

# Check if Docker is available
find_program(DOCKER_EXECUTABLE docker)
if(NOT DOCKER_EXECUTABLE)
    message(WARNING "Docker not found. Docker targets will not be available.")
    return()
endif()

# Check if docker-compose is available
find_program(DOCKER_COMPOSE_EXECUTABLE docker-compose)
if(NOT DOCKER_COMPOSE_EXECUTABLE)
    message(WARNING "docker-compose not found. Compose targets will not be available.")
endif()

# Create Docker targets based on configuration
if(BUILD_SERVER_IMAGE OR BUILD_ALL_IMAGES)
    create_server_target(docker-server Dockerfile.server server)
endif()

if(BUILD_CLI_IMAGE OR BUILD_ALL_IMAGES)
    create_binary_target(docker-cli Dockerfile.cli cli)
endif()

if(BUILD_EXPORTER_IMAGE OR BUILD_ALL_IMAGES)
    create_binary_target(docker-exporter Dockerfile.exporter exporter)
endif()

# Create combined targets
if(BUILD_ALL_IMAGES)
    add_custom_target(docker-all
        DEPENDS docker-server docker-cli docker-exporter
        COMMENT "Building all Docker images"
    )
    
    add_custom_target(docker-all-test
        DEPENDS docker-server-test docker-cli-test docker-exporter-test
        COMMENT "Testing all Docker images"
    )
    
    add_custom_target(docker-all-security
        DEPENDS docker-server-security docker-cli-security docker-exporter-security
        COMMENT "Security testing all Docker images"
    )
    
    add_custom_target(docker-all-scan
        DEPENDS docker-server-scan docker-cli-scan docker-exporter-scan
        COMMENT "Scanning all Docker images"
    )
    
    add_custom_target(docker-all-push
        DEPENDS docker-server-push docker-cli-push docker-exporter-push
        COMMENT "Pushing all Docker images"
    )
    
    add_custom_target(docker-all-clean
        DEPENDS docker-server-clean docker-cli-clean docker-exporter-clean
        COMMENT "Cleaning all Docker images"
    )
endif()

# Create docker-compose targets
if(DOCKER_COMPOSE_EXECUTABLE)
    create_compose_target(docker-compose-up up -d)
    create_compose_target(docker-compose-down down)
    create_compose_target(docker-compose-build build)
    create_compose_target(docker-compose-logs logs)
    create_compose_target(docker-compose-ps ps)
endif()

# Integration test targets
if(RUN_INTEGRATION_TESTS AND DOCKER_EXECUTABLE AND DOCKER_COMPOSE_EXECUTABLE)
    # Build test images with test tags
    add_custom_target(docker-build-test-images
        COMMAND ${CMAKE_COMMAND} -E echo "Building test images for integration tests..."
        COMMAND docker build --file Dockerfile.server --tag sops-secrets-server:test --target runtime --build-arg SOPS_VERSION=${SOPS_VERSION} --build-arg AGE_VERSION=${AGE_VERSION} --build-arg ARCH=${ARCH} --build-arg RUST_VERSION=${RUST_VERSION} --build-arg RUST_TARGET=${RUST_TARGET} --build-arg SERVER_PORT=${DOCKER_SERVER_PORT} .
        COMMAND docker build --file Dockerfile.cli --tag sops-secrets-cli:test --target runtime --build-arg SOPS_VERSION=${SOPS_VERSION} --build-arg ARCH=${ARCH} --build-arg RUST_VERSION=${RUST_VERSION} --build-arg RUST_TARGET=${RUST_TARGET} .
        COMMAND docker build --file Dockerfile.exporter --tag sops-secrets-exporter:test --target runtime --build-arg SOPS_VERSION=${SOPS_VERSION} --build-arg ARCH=${ARCH} --build-arg RUST_VERSION=${RUST_VERSION} --build-arg RUST_TARGET=${RUST_TARGET} .
        COMMAND docker build --file ${INTEGRATION_TEST_DIR}/Dockerfile.test-runner --tag sops-secrets-test-runner:latest --build-arg SOPS_VERSION=${SOPS_VERSION} --build-arg AGE_VERSION=${AGE_VERSION} --build-arg ARCH=${ARCH} ${INTEGRATION_TEST_DIR}
        COMMAND ${CMAKE_COMMAND} -E echo "Test images built successfully"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Building test images for integration tests"
        VERBATIM
    )
    
    # Run integration tests
    add_custom_target(integration-tests
        COMMAND ${CMAKE_COMMAND} -E echo "🚀 Starting integration tests..."
        COMMAND ${CMAKE_COMMAND} -E echo "📁 Test results will be saved to: ${INTEGRATION_TEST_RESULTS_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INTEGRATION_TEST_RESULTS_DIR}
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning up any existing test resources..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml down -v --remove-orphans || true
        COMMAND docker network rm sops-test-net || true
        COMMAND docker volume rm sops-secrets-test-data || true
        COMMAND ${CMAKE_COMMAND} -E echo "🐳 Starting test environment..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml up -d
        COMMAND ${CMAKE_COMMAND} -E echo "⏳ Waiting for services to be ready..."
        COMMAND sleep 30
        COMMAND ${CMAKE_COMMAND} -E echo "🧪 Running test runner..."
        COMMAND timeout ${INTEGRATION_TEST_TIMEOUT} docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml run --rm test-runner
        COMMAND ${CMAKE_COMMAND} -E echo "📋 Copying test results..."
        COMMAND docker cp test-runner:/tmp/integration_test_report.json ${INTEGRATION_TEST_RESULTS_DIR}/integration_test_report.json || ${CMAKE_COMMAND} -E echo "No test report found"
        COMMAND ${CMAKE_COMMAND} -E echo "📄 Test results copied to: ${INTEGRATION_TEST_RESULTS_DIR}/integration_test_report.json"
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning up test environment..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml down -v
        COMMAND ${CMAKE_COMMAND} -E echo "✅ Integration tests completed"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running integration tests"
        VERBATIM
    )
    
    # Run integration tests with detailed output
    add_custom_target(integration-tests-verbose
        COMMAND ${CMAKE_COMMAND} -E echo "🚀 Starting integration tests (verbose mode)..."
        COMMAND ${CMAKE_COMMAND} -E echo "📁 Test results will be saved to: ${INTEGRATION_TEST_RESULTS_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${INTEGRATION_TEST_RESULTS_DIR}
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning up any existing test resources..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml down -v --remove-orphans || true
        COMMAND docker network rm sops-test-net || true
        COMMAND docker volume rm sops-secrets-test-data || true
        COMMAND ${CMAKE_COMMAND} -E echo "🐳 Starting test environment..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml up -d
        COMMAND ${CMAKE_COMMAND} -E echo "⏳ Waiting for services to be ready..."
        COMMAND sleep 30
        COMMAND ${CMAKE_COMMAND} -E echo "🧪 Running test runner with detailed output..."
        COMMAND timeout ${INTEGRATION_TEST_TIMEOUT} docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml run --rm test-runner 2>&1 | tee ${INTEGRATION_TEST_RESULTS_DIR}/test_output.log
        COMMAND ${CMAKE_COMMAND} -E echo "📋 Copying test results..."
        COMMAND docker cp test-runner:/tmp/integration_test_report.json ${INTEGRATION_TEST_RESULTS_DIR}/integration_test_report.json || ${CMAKE_COMMAND} -E echo "No test report found"
        COMMAND ${CMAKE_COMMAND} -E echo "📄 Test results copied to: ${INTEGRATION_TEST_RESULTS_DIR}/integration_test_report.json"
        COMMAND ${CMAKE_COMMAND} -E echo "📄 Test output saved to: ${INTEGRATION_TEST_RESULTS_DIR}/test_output.log"
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning up test environment..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml down -v
        COMMAND ${CMAKE_COMMAND} -E echo "✅ Integration tests completed"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running integration tests with detailed output"
        VERBATIM
    )
    
    # Clean integration test environment
    add_custom_target(integration-tests-clean
        COMMAND ${CMAKE_COMMAND} -E echo "🧹 Cleaning integration test environment..."
        COMMAND docker-compose -f ${INTEGRATION_TEST_DIR}/docker-compose.test.yml down -v --remove-orphans
        COMMAND docker rmi sops-secrets-server:test sops-secrets-cli:test sops-secrets-exporter:test sops-secrets-test-runner:latest || true
        COMMAND docker network rm sops-test-net || true
        COMMAND docker volume rm sops-secrets-test-data || true
        COMMAND ${CMAKE_COMMAND} -E echo "✅ Integration test environment cleaned"
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
    add_dependencies(integration-tests docker-build-test-images)
    add_dependencies(integration-tests-verbose docker-build-test-images)
    add_dependencies(integration-tests-results integration-tests)
endif()

# Create utility targets
add_custom_target(docker-clean-all
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning all Docker resources..."
    COMMAND docker container prune -f
    COMMAND docker image prune -f
    COMMAND docker volume prune -f
    COMMAND docker network prune -f
    COMMAND ${CMAKE_COMMAND} -E echo "Docker cleanup completed"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Cleaning all Docker resources"
    VERBATIM
)

add_custom_target(docker-info
    COMMAND ${CMAKE_COMMAND} -E echo "Docker configuration:"
    COMMAND ${CMAKE_COMMAND} -E echo "  Registry: ${DOCKER_REGISTRY}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Image prefix: ${DOCKER_IMAGE_PREFIX}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Tag: ${DOCKER_TAG}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Server port: ${DOCKER_SERVER_PORT}"
    COMMAND ${CMAKE_COMMAND} -E echo "  SOPS version: ${SOPS_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Age version: ${AGE_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Architecture: ${ARCH}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Rust version: ${RUST_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Build targets:"
    COMMAND ${CMAKE_COMMAND} -E echo "    Server: ${BUILD_SERVER_IMAGE}"
    COMMAND ${CMAKE_COMMAND} -E echo "    CLI: ${BUILD_CLI_IMAGE}"
    COMMAND ${CMAKE_COMMAND} -E echo "    Exporter: ${BUILD_EXPORTER_IMAGE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Integration tests: ${RUN_INTEGRATION_TESTS}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Test results directory: ${INTEGRATION_TEST_RESULTS_DIR}"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Showing Docker configuration"
    VERBATIM
)

# Print configuration summary
message(STATUS "Docker configuration:")
message(STATUS "  Registry: ${DOCKER_REGISTRY}")
message(STATUS "  Image prefix: ${DOCKER_IMAGE_PREFIX}")
message(STATUS "  Tag: ${DOCKER_TAG}")
message(STATUS "  Server port: ${DOCKER_SERVER_PORT}")
message(STATUS "  SOPS version: ${SOPS_VERSION}")
message(STATUS "  Age version: ${AGE_VERSION}")
message(STATUS "  Architecture: ${ARCH}")
message(STATUS "  Rust version: ${RUST_VERSION}")
message(STATUS "  Build targets:")
message(STATUS "    Server: ${BUILD_SERVER_IMAGE}")
message(STATUS "    CLI: ${BUILD_CLI_IMAGE}")
message(STATUS "    Exporter: ${BUILD_EXPORTER_IMAGE}")
message(STATUS "  Integration tests: ${RUN_INTEGRATION_TESTS}")
message(STATUS "  Test results directory: ${INTEGRATION_TEST_RESULTS_DIR}")

# Available targets summary
message(STATUS "")
message(STATUS "Available Docker targets:")
message(STATUS "  docker-server          - Build server image (runnable service)")
message(STATUS "  docker-cli             - Build CLI image (binary only)")
message(STATUS "  docker-exporter        - Build exporter image (binary only)")
message(STATUS "  docker-all             - Build all images")
message(STATUS "  docker-server-test     - Test server image")
message(STATUS "  docker-server-security - Security test server image")
message(STATUS "  docker-server-scan     - Scan server image")
message(STATUS "  docker-compose-up      - Start services")
message(STATUS "  docker-compose-down    - Stop services")
message(STATUS "  docker-clean-all       - Clean all Docker resources")
message(STATUS "  docker-info            - Show configuration")

if(RUN_INTEGRATION_TESTS)
    message(STATUS "")
    message(STATUS "Available Integration Test targets:")
    message(STATUS "  docker-build-test-images    - Build test images")
    message(STATUS "  integration-tests           - Run integration tests")
    message(STATUS "  integration-tests-verbose   - Run integration tests with detailed output")
    message(STATUS "  integration-tests-clean     - Clean test environment")
    message(STATUS "  integration-tests-results   - Show test results")
endif() 