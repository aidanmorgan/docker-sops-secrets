#!/usr/bin/env python3
"""
SOPS Secrets Manager Python Client

A Python client for connecting to the SOPS secrets server via HTTP.
Supports getting, creating, and setting secret values with proper encryption.
"""

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional, Union, Tuple, List
import urllib.parse

import aiohttp
import aiofiles


class SopsClientError(Exception):
    """Base exception for SOPS client errors."""
    pass


class SopsClientConfigError(SopsClientError):
    """Configuration error."""
    pass


class SopsClientConnectionError(SopsClientError):
    """Connection error."""
    pass


class SopsClientAuthError(SopsClientError):
    """Authentication/authorization error."""
    pass


class SopsClientSecretError(SopsClientError):
    """Secret operation error."""
    pass


class SopsClient:
    """
    Python client for the SOPS secrets server.
    
    This client provides methods to:
    - Get secrets from the server
    - Create new secrets
    - Update existing secrets
    - Check server health
    - Manage access control (readers/writers)
    
    The client handles age encryption/decryption automatically and manages
    the two-phase write process required by the server. Each operation
    generates a fresh age key pair for security.
    """
    
    def __init__(
        self,
        server_url: str = "http://localhost:3102",
        timeout: int = 30,
        base_directory: str = "/var/tmp/sops-secrets",
        age_keygen_path: str = "/usr/local/bin/age-keygen",
        age_path: str = "/usr/local/bin/age",
        client_name: str = "default-client",
    ):
        """
        Initialize the SOPS client.
        
        Args:
            server_url: URL of the SOPS server
            timeout: Request timeout in seconds
            base_directory: Base directory where secret files are stored
            age_keygen_path: Path to age-keygen executable
            age_path: Path to age executable
            client_name: Client name for X-Client-Name header (used in local mode)
        """
        self.server_url = server_url.rstrip('/')
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.base_directory = Path(base_directory)
        self.age_keygen_path = age_keygen_path
        self.age_path = age_path
        self.client_name = client_name
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    
    async def connect(self):
        """Create HTTP session."""
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
    
    async def close(self):
        """Close HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for requests, including X-Client-Name for local mode."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Name": self.client_name,
        }
        return headers
    
    async def _handle_json_response(self, response: aiohttp.ClientResponse) -> Dict:
        """
        Handle HTTP response and ensure it's parsed as JSON.
        
        Args:
            response: The HTTP response object
            
        Returns:
            Parsed JSON response data
            
        Raises:
            SopsClientError: If response cannot be parsed as JSON
        """
        try:
            return await response.json()
        except (json.JSONDecodeError, aiohttp.ContentTypeError):
            # Fallback to text if JSON parsing fails
            error_text = await response.text()
            raise SopsClientError(f"Invalid JSON response: {response.status} - {error_text}")
    
    async def _handle_error_response(self, response: aiohttp.ClientResponse) -> None:
        """
        Handle error responses and raise appropriate exceptions.
        
        Args:
            response: The HTTP response object
            
        Raises:
            SopsClientAuthError: For 403 errors
            SopsClientSecretError: For other errors
        """
        try:
            error_data = await response.json()
            error_msg = error_data.get('message', 'Unknown error')
            
            if response.status == 403:
                raise SopsClientAuthError(error_msg)
            elif response.status == 404:
                raise SopsClientSecretError(error_msg)
            else:
                raise SopsClientSecretError(f"HTTP {response.status}: {error_msg}")
        except (json.JSONDecodeError, aiohttp.ContentTypeError):
            # Fallback to text if JSON parsing fails
            error_text = await response.text()
            if response.status == 403:
                raise SopsClientAuthError(f"Access denied: {error_text}")
            else:
                raise SopsClientSecretError(f"HTTP {response.status}: {error_text}")

    
    async def _generate_age_key_pair(self) -> Tuple[str, str]:
        """
        Generate a new age key pair for this operation.
        
        Returns:
            Tuple of (public_key, private_key)
            
        Raises:
            SopsClientError: If key generation fails
        """
        try:
            # Use age-keygen to generate a new key pair (outputs to stdout)
            process = await asyncio.create_subprocess_exec(
                self.age_keygen_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise SopsClientError(f"Failed to generate age key pair: {stderr.decode()}")
            
            # Parse the output to extract both keys
            output = stdout.decode().strip()
            lines = output.split('\n')
            
            private_key = None
            public_key = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('AGE-SECRET-KEY-'):
                    private_key = line
                elif line.startswith('# public key: '):
                    # Extract the public key from the comment line
                    public_key = line.replace('# public key: ', '').strip()
                elif line.startswith('age1') and not line.startswith('# public key: '):
                    # Fallback: direct public key line
                    public_key = line
            
            if not private_key or not public_key:
                raise SopsClientError("Failed to parse age key pair output")
            
            return public_key, private_key
            
        except FileNotFoundError:
            raise SopsClientError(f"age-keygen command not found at {self.age_keygen_path}. Please install age.")
        except Exception as e:
            raise SopsClientError(f"Failed to generate age key pair: {e}")
    

    
    async def health_check(self) -> Dict:
        """
        Check server health.
        
        Returns:
            Health check response from server
            
        Raises:
            SopsClientConnectionError: If server is unreachable
            SopsClientError: If health check fails
        """
        await self.connect()
        
        try:
            headers = self._get_headers()
            async with self.session.get(f"{self.server_url}/health", headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    await self._handle_error_response(response)
        except aiohttp.ClientError as e:
            raise SopsClientConnectionError(f"Failed to connect to server: {e}")
    
    async def get_secret(self, secret_name: str) -> str:
        """
        Get a secret from the server.
        
        Args:
            secret_name: Name of the secret to retrieve
            
        Returns:
            The decrypted secret value
            
        Raises:
            SopsClientAuthError: If access is denied
            SopsClientSecretError: If secret doesn't exist or other error
            SopsClientConnectionError: If server is unreachable
        """
        await self.connect()
        
        # Generate a fresh key pair for this operation
        public_key, private_key = await self._generate_age_key_pair()
        
        try:
            # Prepare the request
            request_data = {
                "public_key": public_key
            }
            
            headers = self._get_headers()
            async with self.session.post(
                f"{self.server_url}/secret/{urllib.parse.quote(secret_name)}",
                json=request_data,
                headers=headers
            ) as response:
                
                if response.status == 200:
                    response_data = await response.json()
                    return await self._read_and_decrypt_secret(response_data, private_key)
                else:
                    await self._handle_error_response(response)
                    
        except aiohttp.ClientError as e:
            raise SopsClientConnectionError(f"Failed to connect to server: {e}")
        except (SopsClientAuthError, SopsClientSecretError):
            raise
        except Exception as e:
            raise SopsClientError(f"Unexpected error getting secret: {e}")
    
    async def _read_and_decrypt_secret(self, response_data: Dict, private_key: str) -> str:
        """
        Read and decrypt a secret file from the base directory.
        
        Args:
            response_data: Response from get_secret endpoint
            private_key: Private key to decrypt with
            
        Returns:
            Decrypted secret value
        """
        file_path = response_data.get('file_path')
        if not file_path:
            raise SopsClientSecretError("No file path in response")
        
        # Construct the full file path relative to base directory
        full_file_path = self.base_directory / file_path
        
        # Read the encrypted file
        try:
            async with aiofiles.open(full_file_path, 'rb') as f:
                encrypted_data = await f.read()
                
        except FileNotFoundError:
            raise SopsClientSecretError(f"Secret file not found: {full_file_path}")
        except Exception as e:
            raise SopsClientSecretError(f"Failed to read secret file {full_file_path}: {e}")
        
        # Decrypt the data using age
        try:
            decrypted_data = await self._decrypt_with_age(encrypted_data, private_key)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise SopsClientSecretError(f"Failed to decrypt secret: {e}")
    
    async def _decrypt_with_age(self, encrypted_data: bytes, private_key: str) -> bytes:
        """
        Decrypt data using age.
        
        Args:
            encrypted_data: Encrypted data to decrypt
            private_key: Private key to decrypt with
            
        Returns:
            Decrypted data
        """
        # Use age to decrypt with private key provided as --identity argument
        process = await asyncio.create_subprocess_exec(
            self.age_path, '--decrypt', '--identity', private_key,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate(input=encrypted_data)
        
        if process.returncode != 0:
            raise SopsClientSecretError(f"Age decryption failed: {stderr.decode()}")
        
        return stdout
    
    async def create_secret(self, secret_name: str, secret_value: str) -> str:
        """
        Create a new secret.
        
        Args:
            secret_name: Name of the secret to create
            secret_value: Value of the secret
            
        Returns:
            "created" on success
            
        Raises:
            SopsClientAuthError: If access is denied
            SopsClientSecretError: If secret already exists or other error
            SopsClientConnectionError: If server is unreachable
        """
        return await self._write_secret(secret_name, secret_value, is_update=False)
    
    async def update_secret(self, secret_name: str, secret_value: str) -> str:
        """
        Update an existing secret.
        
        Args:
            secret_name: Name of the secret to update
            secret_value: New value of the secret
            
        Returns:
            "updated" on success
            
        Raises:
            SopsClientAuthError: If access is denied
            SopsClientSecretError: If secret doesn't exist or other error
            SopsClientConnectionError: If server is unreachable
        """
        return await self._write_secret(secret_name, secret_value, is_update=True)
    
    async def set_secret(self, secret_name: str, secret_value: str) -> str:
        """
        Set a secret (create if doesn't exist, update if it does).
        
        Args:
            secret_name: Name of the secret to set
            secret_value: Value of the secret
            
        Returns:
            "created" or "updated" on success
            
        Raises:
            SopsClientAuthError: If access is denied
            SopsClientSecretError: If operation fails
            SopsClientConnectionError: If server is unreachable
        """
        return await self._write_secret(secret_name, secret_value, is_update=None)
    
    async def _write_secret(self, secret_name: str, secret_value: str, is_update: Optional[bool]) -> str:
        """
        Internal method to write a secret using the two-phase process.
        
        Args:
            secret_name: Name of the secret
            secret_value: Value to store
            is_update: True for update, False for create, None for auto-detect
            
        Returns:
            Success message
        """
        await self.connect()
        
        # Calculate secret hash
        secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()
        
        # Phase 1: Initialize write operation
        init_request = {
            "secret_name": secret_name,
            "secret_hash": secret_hash
        }
        
        try:
            headers = self._get_headers()
            async with self.session.post(
                f"{self.server_url}/secret/{urllib.parse.quote(secret_name)}/write/init",
                json=init_request,
                headers=headers
            ) as response:
                
                if response.status == 200:
                    init_response = await response.json()
                else:
                    await self._handle_error_response(response)
        
        except aiohttp.ClientError as e:
            raise SopsClientConnectionError(f"Failed to connect to server: {e}")
        
        # Phase 2: Encrypt and write the secret to the file
        try:
            encrypted_data = await self._encrypt_with_age(secret_value, init_response['public_key'])
            
            # Write encrypted data to the file in the base directory
            file_path = self.base_directory / init_response['file_path']
            
            # Ensure the directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(encrypted_data)
        
        except Exception as e:
            raise SopsClientSecretError(f"Failed to encrypt and write secret: {e}")
        
        # Phase 3: Complete the write operation
        try:
            headers = self._get_headers()
            async with self.session.post(
                f"{self.server_url}/secret/{urllib.parse.quote(secret_name)}/write/complete",
                headers=headers
            ) as response:
                
                if response.status == 200:
                    response_data = await response.json()
                    return response_data.get('message', 'Secret written successfully')
                else:
                    await self._handle_error_response(response)
        
        except aiohttp.ClientError as e:
            raise SopsClientConnectionError(f"Failed to connect to server: {e}")
    
    async def _encrypt_with_age(self, data: str, public_key: str) -> bytes:
        """
        Encrypt data using age.
        
        Args:
            data: Data to encrypt
            public_key: Age public key to encrypt with
            
        Returns:
            Encrypted data
        """
        # Use age to encrypt with public key provided as --recipient argument
        process = await asyncio.create_subprocess_exec(
            self.age_path, '--encrypt', '--recipient', public_key,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate(input=data.encode())
        
        if process.returncode != 0:
            raise SopsClientSecretError(f"Age encryption failed: {stderr.decode()}")
        
        return stdout


# Convenience functions for common operations
async def get_secret(
    server_url: str, 
    secret_name: str, 
    base_directory: str = "/var/tmp/sops-secrets",
    age_keygen_path: str = "/usr/local/bin/age-keygen",
    age_path: str = "/usr/local/bin/age",
    client_name: str = "default-client"
) -> str:
    """
    Convenience function to get a secret.
    
    Args:
        server_url: URL of the SOPS server
        secret_name: Name of the secret to retrieve
        base_directory: Base directory where secret files are stored
        age_keygen_path: Path to age-keygen executable
        age_path: Path to age executable
        client_name: Client name for X-Client-Name header
        
    Returns:
        The decrypted secret value
    """
    async with SopsClient(
        server_url=server_url,
        base_directory=base_directory,
        age_keygen_path=age_keygen_path,
        age_path=age_path,
        client_name=client_name
    ) as client:
        return await client.get_secret(secret_name)


async def set_secret(
    server_url: str, 
    secret_name: str, 
    secret_value: str, 
    base_directory: str = "/var/tmp/sops-secrets",
    age_keygen_path: str = "/usr/local/bin/age-keygen",
    age_path: str = "/usr/local/bin/age",
    client_name: str = "default-client"
) -> str:
    """
    Convenience function to set a secret.
    
    Args:
        server_url: URL of the SOPS server
        secret_name: Name of the secret to set
        secret_value: Value of the secret
        base_directory: Base directory where secret files are stored
        age_keygen_path: Path to age-keygen executable
        age_path: Path to age executable
        client_name: Client name for X-Client-Name header
        
    Returns:
        "created" or "updated" on success
    """
    async with SopsClient(
        server_url=server_url,
        base_directory=base_directory,
        age_keygen_path=age_keygen_path,
        age_path=age_path,
        client_name=client_name
    ) as client:
        return await client.set_secret(secret_name, secret_value)


async def health_check(server_url: str) -> Dict:
    """
    Convenience function to check server health.
    
    Args:
        server_url: URL of the SOPS server
        
    Returns:
        Health check response from server
    """
    async with SopsClient(server_url=server_url) as client:
        return await client.health_check() 