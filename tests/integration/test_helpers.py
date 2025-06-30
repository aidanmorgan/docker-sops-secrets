"""
Test helpers for SOPS Secrets Manager integration tests.

This module provides helper classes and utilities for running comprehensive
integration tests against the SOPS secrets management system.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import requests
import docker
import yaml
from dataclasses import dataclass, asdict


class TestStatus(Enum):
    """Test result status."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TestResult:
    """Test result data structure."""
    name: str
    status: TestStatus
    duration: float
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "status": self.status.value,
            "duration": self.duration,
            "error": self.error,
            "details": self.details
        }


class TestHelper:
    """Helper class for making HTTP requests to the server."""
    
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.session = requests.Session()
        self.session.timeout = 30
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        response = self.session.get(f"{self.server_url}/health")
        response.raise_for_status()
        return response.json()
    
    async def get_secret(self, secret_name: str, public_key: str) -> Dict[str, Any]:
        """Get a secret from the server."""
        payload = {"public_key": public_key}
        response = self.session.post(
            f"{self.server_url}/secret/{secret_name}",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    async def write_secret_init(self, secret_name: str, secret_hash: str) -> Dict[str, Any]:
        """Initialize a write operation."""
        payload = {
            "secret_name": secret_name,
            "secret_hash": secret_hash
        }
        response = self.session.post(
            f"{self.server_url}/secret/{secret_name}/write/init",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    async def write_secret_complete(self, secret_name: str) -> Dict[str, Any]:
        """Complete a write operation."""
        response = self.session.post(
            f"{self.server_url}/secret/{secret_name}/write/complete"
        )
        response.raise_for_status()
        return response.json()


class SecretManager:
    """Helper class for managing secrets in the SOPS file."""
    
    def __init__(self, sops_file_path: str, master_key_path: str):
        self.sops_file_path = sops_file_path
        self.master_key_path = master_key_path
    
    async def create_secret(self, name: str, value: str, owner: str, 
                          readers: List[str], writers: List[str]) -> None:
        """Create a new secret with access control."""
        # Use the CLI to create the secret
        cmd = [
            "sops-secrets-cli",
            "--file", self.sops_file_path,
            "--master-key", self.master_key_path,
            "add-owned",
            "--owner", owner,
            "--name", name,
            "--value", value,
            "--readers", ",".join(readers),
            "--writers", ",".join(writers)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to create secret: {result.stderr}")
    
    async def get_secret(self, name: str, owner: str) -> str:
        """Get a secret value."""
        cmd = [
            "sops-secrets-cli",
            "--file", self.sops_file_path,
            "--master-key", self.master_key_path,
            "get-owned",
            "--owner", owner,
            "--name", name
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to get secret: {result.stderr}")
        
        return result.stdout.strip()
    
    async def update_secret(self, name: str, value: str) -> None:
        """Update a secret value."""
        cmd = [
            "sops-secrets-cli",
            "--file", self.sops_file_path,
            "--master-key", self.master_key_path,
            "update",
            "--name", name,
            "--value", value
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to update secret: {result.stderr}")
    
    async def check_access(self, secret_name: str, user: str, operation: str) -> bool:
        """Check if a user has access to a secret."""
        cmd = [
            "sops-secrets-cli",
            "--file", self.sops_file_path,
            "--master-key", self.master_key_path,
            "access",
            "can-read" if operation == "read" else "can-write",
            "--secret", secret_name,
            "--user", user
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0


class DockerHelper:
    """Helper class for Docker operations."""
    
    def __init__(self):
        self.client = docker.from_env()
    
    def get_containers(self) -> List[docker.models.containers.Container]:
        """Get all containers."""
        return self.client.containers.list()
    
    def get_container_by_name(self, name: str) -> Optional[docker.models.containers.Container]:
        """Get a container by name."""
        try:
            return self.client.containers.get(name)
        except docker.errors.NotFound:
            return None
    
    def get_container_ip(self, container_name: str) -> Optional[str]:
        """Get the IP address of a container."""
        container = self.get_container_by_name(container_name)
        if container:
            networks = container.attrs['NetworkSettings']['Networks']
            for network_name, network_info in networks.items():
                if network_info.get('IPAddress'):
                    return network_info['IPAddress']
        return None
    
    def exec_command(self, container_name: str, command: List[str]) -> Tuple[int, str, str]:
        """Execute a command in a container."""
        container = self.get_container_by_name(container_name)
        if not container:
            raise Exception(f"Container {container_name} not found")
        
        result = container.exec_run(command)
        return result.exit_code, result.output.decode('utf-8'), result.output.decode('utf-8')
    
    def get_container_labels(self, container_name: str) -> Dict[str, str]:
        """Get labels of a container."""
        container = self.get_container_by_name(container_name)
        if container:
            return container.labels
        return {}
    
    def get_container_image(self, container_name: str) -> Optional[str]:
        """Get the image name of a container."""
        container = self.get_container_by_name(container_name)
        if container:
            return container.image.tags[0] if container.image.tags else container.image.id
        return None


class AgeKeyManager:
    """Helper class for managing age keys."""
    
    def __init__(self):
        self.keys_dir = "/tmp/test-age-keys"
        os.makedirs(self.keys_dir, exist_ok=True)
    
    def generate_key_pair(self, name: str) -> Tuple[str, str]:
        """Generate a new age key pair."""
        private_key_path = os.path.join(self.keys_dir, f"{name}.key")
        public_key_path = os.path.join(self.keys_dir, f"{name}.pub")
        
        # Generate private key
        result = subprocess.run(
            ["age-keygen", "-o", private_key_path],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to generate private key: {result.stderr}")
        
        # Extract public key
        result = subprocess.run(
            ["age-keygen", "-y", private_key_path],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to extract public key: {result.stderr}")
        
        public_key = result.stdout.strip()
        
        # Save public key to file
        with open(public_key_path, 'w') as f:
            f.write(public_key)
        
        return private_key_path, public_key_path
    
    def encrypt_file(self, input_file: str, output_file: str, public_key: str) -> None:
        """Encrypt a file with age."""
        result = subprocess.run([
            "age", "-e", "-r", public_key, "-o", output_file, input_file
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Failed to encrypt file: {result.stderr}")
    
    def decrypt_file(self, input_file: str, output_file: str, private_key_path: str) -> None:
        """Decrypt a file with age."""
        result = subprocess.run([
            "age", "-d", "-i", private_key_path, "-o", output_file, input_file
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Failed to decrypt file: {result.stderr}")
    
    def cleanup_keys(self, name: str) -> None:
        """Clean up age keys for a test."""
        private_key_path = os.path.join(self.keys_dir, f"{name}.key")
        public_key_path = os.path.join(self.keys_dir, f"{name}.pub")
        
        for path in [private_key_path, public_key_path]:
            if os.path.exists(path):
                os.remove(path)


class TestTimer:
    """Context manager for timing tests."""
    
    def __init__(self, test_name: str):
        self.test_name = test_name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.duration = time.time() - self.start_time
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time."""
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time


def run_test(test_name: str, test_func, *args, **kwargs) -> TestResult:
    """Decorator to run a test and capture results."""
    with TestTimer(test_name) as timer:
        try:
            result = test_func(*args, **kwargs)
            if result:
                return TestResult(
                    name=test_name,
                    status=TestStatus.PASSED,
                    duration=timer.elapsed
                )
            else:
                return TestResult(
                    name=test_name,
                    status=TestStatus.FAILED,
                    duration=timer.elapsed,
                    error="Test returned False"
                )
        except Exception as e:
            return TestResult(
                name=test_name,
                status=TestStatus.FAILED,
                duration=timer.elapsed,
                error=str(e)
            )


async def run_async_test(test_name: str, test_func, *args, **kwargs) -> TestResult:
    """Decorator to run an async test and capture results."""
    with TestTimer(test_name) as timer:
        try:
            result = await test_func(*args, **kwargs)
            if result:
                return TestResult(
                    name=test_name,
                    status=TestStatus.PASSED,
                    duration=timer.elapsed
                )
            else:
                return TestResult(
                    name=test_name,
                    status=TestStatus.FAILED,
                    duration=timer.elapsed,
                    error="Test returned False"
                )
        except Exception as e:
            return TestResult(
                name=test_name,
                status=TestStatus.FAILED,
                duration=timer.elapsed,
                error=str(e)
            )


def assert_condition(condition: bool, message: str):
    """Assert a condition with a custom message."""
    if not condition:
        raise AssertionError(message)


def assert_response_status(response: requests.Response, expected_status: int):
    """Assert that a response has the expected status code."""
    if response.status_code != expected_status:
        raise AssertionError(
            f"Expected status {expected_status}, got {response.status_code}. "
            f"Response: {response.text}"
        )


def assert_json_contains(response_json: Dict[str, Any], expected_keys: List[str]):
    """Assert that a JSON response contains expected keys."""
    for key in expected_keys:
        if key not in response_json:
            raise AssertionError(f"Response missing expected key: {key}")


def create_temp_file(content: str) -> str:
    """Create a temporary file with content."""
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path


def cleanup_temp_file(path: str):
    """Clean up a temporary file."""
    if os.path.exists(path):
        os.remove(path) 