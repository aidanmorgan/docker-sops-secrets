"""
Pytest configuration and shared fixtures for integration tests.

This file contains pytest configuration and shared fixtures that can be used
across all integration tests.
"""

import pytest
import asyncio
import os
import tempfile
import shutil
from typing import Generator, Dict, Any
from test_helpers import TestHelper, SecretManager, DockerHelper, AgeKeyManager


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def server_url() -> str:
    """Get the SOPS server URL from environment or use default."""
    return os.getenv('SOPS_SERVER_URL', 'http://localhost:3000')


@pytest.fixture(scope="session")
def master_key_path() -> str:
    """Get the master key path from environment or use default."""
    return os.getenv('MASTER_KEY_PATH', '/run/secrets/master_key.age')


@pytest.fixture(scope="session")
def sops_file_path() -> str:
    """Get the SOPS file path from environment or use default."""
    return os.getenv('SOPS_FILE_PATH', '/run/secrets/secrets.yaml')


@pytest.fixture(scope="session")
def test_helper(server_url: str) -> TestHelper:
    """Create a test helper instance."""
    return TestHelper(server_url)


@pytest.fixture(scope="session")
def secret_manager(sops_file_path: str, master_key_path: str) -> SecretManager:
    """Create a secret manager instance."""
    return SecretManager(sops_file_path, master_key_path)


@pytest.fixture(scope="session")
def docker_helper() -> DockerHelper:
    """Create a Docker helper instance."""
    return DockerHelper()


@pytest.fixture(scope="session")
def age_manager() -> AgeKeyManager:
    """Create an age key manager instance."""
    return AgeKeyManager()


@pytest.fixture(scope="function")
def temp_secrets_dir() -> Generator[str, None, None]:
    """Create a temporary directory for test secrets."""
    temp_dir = tempfile.mkdtemp(prefix="sops-test-")
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def test_secrets() -> Dict[str, Dict[str, Any]]:
    """Provide test secrets data."""
    return {
        "database_password": {
            "value": "super-secret-db-password-123",
            "owner": "webapp",
            "readers": ["webapp", "api-server"],
            "writers": ["webapp"]
        },
        "api_key": {
            "value": "sk-test-1234567890abcdef",
            "owner": "api-server",
            "readers": ["api-server", "webapp"],
            "writers": ["api-server"]
        },
        "redis_password": {
            "value": "redis-secret-password-456",
            "owner": "cache-service",
            "readers": ["cache-service"],
            "writers": ["cache-service"]
        },
        "jwt_secret": {
            "value": "jwt-super-secret-key-789",
            "owner": "auth-service",
            "readers": ["auth-service"],
            "writers": ["auth-service"]
        }
    }


@pytest.fixture(scope="function")
def test_containers() -> Dict[str, str]:
    """Provide expected test container names."""
    return {
        "server": "sops-secrets-server-test",
        "authorized_client": "authorized-client-test",
        "unauthorized_client": "unauthorized-client-test",
        "untrusted_client": "untrusted-client-test",
        "exporter_client": "exporter-client-test",
        "test_runner": "test-runner"
    }


# Pytest configuration
def pytest_configure(config):
    """Configure pytest for integration tests."""
    # Add custom markers
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security-related"
    )
    config.addinivalue_line(
        "markers", "docker: mark test as requiring Docker"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add default markers."""
    for item in items:
        # Add integration marker to all tests in this directory
        item.add_marker(pytest.mark.integration)
        
        # Add docker marker to tests that use docker_helper
        if "docker_helper" in item.fixturenames:
            item.add_marker(pytest.mark.docker)
        
        # Add slow marker to tests that might take time
        if any(keyword in item.name.lower() for keyword in ["performance", "stress", "load"]):
            item.add_marker(pytest.mark.slow)
        
        # Add security marker to security-related tests
        if any(keyword in item.name.lower() for keyword in ["security", "auth", "access", "permission"]):
            item.add_marker(pytest.mark.security) 