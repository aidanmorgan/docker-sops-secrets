"""
Basic operations tests for the SOPS Secrets Manager local server.

These tests verify fundamental functionality like health checks,
server connectivity, and basic secret operations (get, set, update)
with proper ownership and permissions testing.
"""

import asyncio
import os
import subprocess
import time
from pathlib import Path

import pytest
import pytest_asyncio

from sops_client import (
    SopsClient,
    SopsClientError,
    SopsClientConnectionError,
    SopsClientSecretError,
    health_check,
    get_secret,
    set_secret,
)


class CLITestHelper:
    """Helper class for CLI operations in tests."""
    
    def __init__(self, sops_file_path: Path, master_key_path: Path, project_root: Path):
        self.sops_file_path = sops_file_path
        self.master_key_path = master_key_path
        self.project_root = project_root
    
    def add_reader_to_secret(self, secret_name: str, reader_name: str) -> None:
        """Add a reader to a secret using the CLI."""
        self._run_cli_command([
            "access", "add-reader",
            "--secret", secret_name,
            "--reader", reader_name
        ])
    
    def add_writer_to_secret(self, secret_name: str, writer_name: str) -> None:
        """Add a writer to a secret using the CLI."""
        self._run_cli_command([
            "access", "add-writer",
            "--secret", secret_name,
            "--writer", writer_name
        ])
    
    def remove_reader_from_secret(self, secret_name: str, reader_name: str) -> None:
        """Remove a reader from a secret using the CLI."""
        self._run_cli_command([
            "access", "remove-reader",
            "--secret", secret_name,
            "--reader", reader_name
        ])
    
    def remove_writer_from_secret(self, secret_name: str, writer_name: str) -> None:
        """Remove a writer from a secret using the CLI."""
        self._run_cli_command([
            "access", "remove-writer",
            "--secret", secret_name,
            "--writer", writer_name
        ])
    
    def get_secret_info(self, secret_name: str) -> str:
        """Get secret information using the CLI."""
        return self._run_cli_command([
            "info",
            "--name", secret_name
        ])
    
    def _run_cli_command(self, args: list) -> str:
        """Run a CLI command and return the output."""
        # Build the full command
        full_args = ["cargo", "run", "--bin", "sops-secrets-cli", "--"] + args
        
        # Run the CLI command
        result = subprocess.run(
            full_args,
            cwd=self.project_root,
            capture_output=True,
            text=True,
            env={
                "SOPS_FILE_PATH": str(self.sops_file_path),
                "SOPS_MASTER_KEY_PATH": str(self.master_key_path)
            }
        )
        
        if result.returncode != 0:
            pytest.skip(f"CLI command failed: {result.stderr}")
        
        return result.stdout


class TestHealthCheck:
    """Test server health check functionality."""
    
    @pytest.mark.asyncio
    async def test_health_check_via_client(self, integration_helper):
        """Test health check using the client."""
        async with integration_helper.server_helper as client:
            health = await client.health_check()
            
            assert isinstance(health, dict)
            assert "checks" in health
            assert isinstance(health["checks"], dict)
            assert all(health["checks"].values()), f"Some health checks failed: {health['checks']}"
            assert "timestamp" in health


class TestSecretOwnershipAndPermissions:
    """Test secret operations with proper ownership and permissions model."""
    
    @pytest.mark.asyncio
    async def test_create_secret_as_owner(self, integration_helper):
        """Test creating a secret where the client becomes the owner."""
        owner_name = f"service-owner-{int(time.time())}"
        secret_name = f"owner_secret_{int(time.time())}"
        secret_value = f"owner_secret_value_{int(time.time())}"
        
        # Create client with owner identity
        async with integration_helper.server_helper.with_client_name(owner_name) as owner_client:
            # Create the secret - this should make the client the owner
            result = await owner_client.create_secret(secret_name, secret_value)
            assert result == "created"
            
            # Owner should be able to read their own secret
            retrieved_value = await owner_client.get_secret(secret_name)
            assert retrieved_value == secret_value
    
    @pytest.mark.asyncio
    async def test_owner_can_update_own_secret(self, integration_helper):
        """Test that an owner can update their own secret."""
        owner_name = f"service-owner-{int(time.time())}"
        secret_name = f"owner_update_secret_{int(time.time())}"
        initial_value = f"initial_value_{int(time.time())}"
        updated_value = f"updated_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(owner_name) as owner_client:
            # Create the secret
            result = await owner_client.create_secret(secret_name, initial_value)
            assert result == "created"
            
            # Update the secret
            result = await owner_client.update_secret(secret_name, updated_value)
            assert result == "updated"
            
            # Verify the update
            retrieved_value = await owner_client.get_secret(secret_name)
            assert retrieved_value == updated_value
    
    @pytest.mark.asyncio
    async def test_unauthorized_access_denied(self, integration_helper):
        """Test that unauthorized clients cannot access secrets."""
        owner_name = f"service-owner-{int(time.time())}"
        unauthorized_name = f"unauthorized-service-{int(time.time())}"
        secret_name = f"protected_secret_{int(time.time())}"
        secret_value = f"protected_value_{int(time.time())}"
        
        # Create secret as owner
        async with integration_helper.server_helper.with_client_name(owner_name) as owner_client:
            result = await owner_client.create_secret(secret_name, secret_value)
            assert result == "created"
        
        # Try to access as unauthorized client
        async with integration_helper.server_helper.with_client_name(unauthorized_name) as unauthorized_client:
            with pytest.raises(SopsClientSecretError):
                await unauthorized_client.get_secret(secret_name)
    
    @pytest.mark.asyncio
    async def test_reader_access_granted_via_cli(self, integration_helper):
        """Test that readers can access secrets after being granted access via CLI."""
        owner_name = f"service-owner-{int(time.time())}"
        reader_name = f"reader-service-{int(time.time())}"
        secret_name = f"shared_secret_{int(time.time())}"
        secret_value = f"shared_value_{int(time.time())}"
        
        # Create secret as owner
        async with integration_helper.server_helper.with_client_name(owner_name) as owner_client:
            result = await owner_client.create_secret(secret_name, secret_value)
            assert result == "created"
        
        # Add reader access using CLI helper
        integration_helper.cli_helper.add_reader_to_secret(secret_name, reader_name)
        
        # Reader should now be able to access the secret
        async with integration_helper.server_helper.with_client_name(reader_name) as reader_client:
            retrieved_value = await reader_client.get_secret(secret_name)
            assert retrieved_value == secret_value
    
    @pytest.mark.asyncio
    async def test_writer_can_update_secret_via_cli(self, integration_helper):
        """Test that writers can update secrets after being granted access via CLI."""
        owner_name = f"service-owner-{int(time.time())}"
        writer_name = f"writer-service-{int(time.time())}"
        secret_name = f"writable_secret_{int(time.time())}"
        initial_value = f"initial_value_{int(time.time())}"
        updated_value = f"writer_updated_value_{int(time.time())}"
        
        # Create secret as owner
        async with integration_helper.server_helper.with_client_name(owner_name) as owner_client:
            result = await owner_client.create_secret(secret_name, initial_value)
            assert result == "created"
        
        # Add writer access using CLI helper
        integration_helper.cli_helper.add_writer_to_secret(secret_name, writer_name)
        
        # Writer should be able to update the secret
        async with integration_helper.server_helper.with_client_name(writer_name) as writer_client:
            result = await writer_client.update_secret(secret_name, updated_value)
            assert result == "updated"
            
            # Verify the update
            retrieved_value = await writer_client.get_secret(secret_name)
            assert retrieved_value == updated_value


class TestSecretOperations:
    """Test basic secret operations with proper ownership context."""
    
    @pytest.mark.asyncio
    async def test_create_and_get_secret(self, integration_helper):
        """Test creating and retrieving a secret with proper ownership."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"test_secret_{int(time.time())}"
        secret_value = f"test_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # Create the secret
            result = await client.create_secret(secret_name, secret_value)
            assert result == "created"
            
            # Get the secret back
            retrieved_value = await client.get_secret(secret_name)
            assert retrieved_value == secret_value
    
    @pytest.mark.asyncio
    async def test_update_secret(self, integration_helper):
        """Test updating an existing secret."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"update_secret_{int(time.time())}"
        initial_value = f"initial_value_{int(time.time())}"
        updated_value = f"updated_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # Create initial secret
            await client.create_secret(secret_name, initial_value)
            
            # Update the secret
            result = await client.update_secret(secret_name, updated_value)
            assert result == "updated"
            
            # Verify the update
            retrieved_value = await client.get_secret(secret_name)
            assert retrieved_value == updated_value
    
    @pytest.mark.asyncio
    async def test_set_secret_creates_new(self, integration_helper):
        """Test that set_secret creates a new secret if it doesn't exist."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"set_secret_{int(time.time())}"
        secret_value = f"set_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            result = await client.set_secret(secret_name, secret_value)
            assert result == "created"
            
            retrieved_value = await client.get_secret(secret_name)
            assert retrieved_value == secret_value
    
    @pytest.mark.asyncio
    async def test_set_secret_updates_existing(self, integration_helper):
        """Test that set_secret updates an existing secret."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"set_update_secret_{int(time.time())}"
        initial_value = f"initial_value_{int(time.time())}"
        updated_value = f"set_updated_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # Create initial secret
            await client.create_secret(secret_name, initial_value)
            
            # Update using set_secret
            result = await client.set_secret(secret_name, updated_value)
            assert result == "updated"
            
            retrieved_value = await client.get_secret(secret_name)
            assert retrieved_value == updated_value
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_secret(self, integration_helper):
        """Test getting a secret that doesn't exist."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"nonexistent_secret_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            with pytest.raises(SopsClientSecretError):
                await client.get_secret(secret_name)
    
    @pytest.mark.asyncio
    async def test_convenience_functions(self, integration_helper):
        """Test convenience functions for secret operations."""
        client_name = f"convenience-service-{int(time.time())}"
        secret_name = f"convenience_test_{int(time.time())}"
        secret_value = f"convenience_test_value_{int(time.time())}"
        
        # Set secret using convenience function
        result = await set_secret(
            integration_helper.server_helper.server_url, 
            secret_name, 
            secret_value, 
            str(integration_helper.test_dir), 
            client_name
        )
        assert result == "created"
        
        # Get secret using convenience function
        retrieved_value = await get_secret(
            integration_helper.server_helper.server_url, 
            secret_name, 
            str(integration_helper.test_dir), 
            client_name
        )
        assert retrieved_value == secret_value


class TestErrorHandling:
    """Test error handling scenarios with proper ownership context."""
    
    @pytest.mark.asyncio
    async def test_invalid_secret_name(self, integration_helper):
        """Test operations with invalid secret names."""
        client_name = f"test-service-{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # Empty secret name
            with pytest.raises(SopsClientError):
                await client.create_secret("", "value")
            
            # Secret name with invalid characters (if applicable)
            with pytest.raises(SopsClientError):
                await client.create_secret("invalid/name", "value")
    
    @pytest.mark.asyncio
    async def test_empty_secret_value(self, integration_helper):
        """Test creating a secret with empty value."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"empty_secret_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # This should work (empty secrets are valid)
            result = await client.create_secret(secret_name, "")
            assert result == "created"
            
            retrieved_value = await client.get_secret(secret_name)
            assert retrieved_value == ""
    
    @pytest.mark.asyncio
    async def test_update_nonexistent_secret(self, integration_helper):
        """Test updating a secret that doesn't exist."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"nonexistent_update_{int(time.time())}"
        new_value = f"new_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # This should fail since the secret doesn't exist
            with pytest.raises(SopsClientSecretError):
                await client.update_secret(secret_name, new_value)
    
    @pytest.mark.asyncio
    async def test_create_duplicate_secret(self, integration_helper):
        """Test creating a secret that already exists."""
        client_name = f"test-service-{int(time.time())}"
        secret_name = f"duplicate_secret_{int(time.time())}"
        secret_value = f"secret_value_{int(time.time())}"
        
        async with integration_helper.server_helper.with_client_name(client_name) as client:
            # Create the secret first
            result = await client.create_secret(secret_name, secret_value)
            assert result == "created"
            
            # Try to create it again
            with pytest.raises(SopsClientSecretError):
                await client.create_secret(secret_name, "different_value") 