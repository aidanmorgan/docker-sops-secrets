"""
Pytest configuration and fixtures for SOPS Secrets Manager integration tests.

This module provides fixtures for testing the local server binary
without requiring Docker containers.
"""

import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import time
import shutil
from pathlib import Path
from typing import AsyncGenerator, Generator, Optional
import uuid
import json

import pytest
import pytest_asyncio

from sops_client import SopsClient


class CLITestHelper:
    """Helper class for CLI operations in tests."""
    
    def __init__(self, sops_file_path: Path, master_key_path: Path, project_root: Path):
        self.sops_file_path = sops_file_path
        self.master_key_path = master_key_path
        self.project_root = project_root
        # Path to the CLI binary in target directory
        self.cli_binary = project_root / "target" / "release" / "sops-secrets-cli"
    
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
        # Check if CLI binary exists
        if not self.cli_binary.exists():
            pytest.skip(f"CLI binary not found at {self.cli_binary}. Run 'make build-cli-binary' first.")
        
        # Build the full command
        full_args = [str(self.cli_binary)] + args
        
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


class ServerTestHelper:
    """Helper class for server operations in tests."""
    
    def __init__(self, server_url: str, test_dir: Path, client_name: str = None):
        self.server_url = server_url
        self.test_dir = test_dir
        self.client_name = client_name or f"test-client-{int(time.time())}"
        self.client = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.client = SopsClient(
            server_url=self.server_url,
            base_directory=str(self.test_dir / "secrets"),  # Use the same directory as the server
            client_name=self.client_name
        )
        await self.client.connect()
        return self.client
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.close()
    
    def with_client_name(self, client_name: str) -> 'ServerTestHelper':
        """Create a new helper with a different client name."""
        return ServerTestHelper(self.server_url, self.test_dir, client_name)


class IntegrationTestHelper:
    """Helper class that manages the complete test environment for integration tests."""
    
    def __init__(self, temp_dir: Path, server_port: int, local_binary: Path):
        self.temp_dir = temp_dir
        self.server_port = server_port
        self.local_binary = local_binary
        self.project_root = Path(__file__).parent.parent.parent
        
        # Create unique test environment with more uniqueness
        self.test_dir = temp_dir / f"test_{int(time.time())}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        self.test_dir.mkdir(exist_ok=True)
        
        # Create results directory for logs
        self.results_dir = Path(__file__).parent / "results"
        self.results_dir.mkdir(exist_ok=True)
        
        # Create test files
        self.master_key_path, self.sops_file_path, self.secrets_dir = self._create_test_environment()
        
        # Initialize helpers
        self.cli_helper = CLITestHelper(self.sops_file_path, self.master_key_path, self.project_root)
        self.server_helper = ServerTestHelper(
            f"http://localhost:{server_port}",
            self.test_dir
        )
        
        # Server process (will be set when started)
        self.server_process = None
    
    def _create_test_environment(
        self,
        sops_file_path: Optional[Path] = None,
        master_key_path: Optional[Path] = None,
        secrets_dir: Optional[Path] = None
    ) -> tuple[Path, Path, Path]:
        """
        Create a test environment with master key, SOPS file, and secrets directory.
        
        Args:
            sops_file_path: Path to the SOPS YAML file (if None, will create one)
            master_key_path: Path to the master key file (if None, will create one)
            secrets_dir: Path to the secrets directory (if None, will create one)
            
        Returns:
            Tuple of (master_key_path, sops_file_path, secrets_dir)
        """
        # Use provided secrets directory or create a new one
        if secrets_dir is None:
            secrets_dir = self.test_dir / "secrets"
            secrets_dir.mkdir(exist_ok=True)
        
        # Use provided master key path or create a new one
        if master_key_path is None:
            master_key_path = self.test_dir / "master_key.age"
            # Clean up any existing file to avoid conflicts
            if master_key_path.exists():
                master_key_path.unlink()
            subprocess.run(
                ["age-keygen", "-o", str(master_key_path)],
                check=True,
                capture_output=True,
            )
        
        # Use provided SOPS file path or create a new one
        if sops_file_path is None:
            sops_file_path = self.test_dir / "secrets.json"
            # Clean up any existing file to avoid conflicts
            if sops_file_path.exists():
                sops_file_path.unlink()
            
            # Extract public key from master key
            result = subprocess.run(
                ["cat", str(master_key_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            
            # Find the public key line
            public_key = None
            for line in result.stdout.split('\n'):
                if line.startswith('# public key: '):
                    public_key = line.replace('# public key: ', '').strip()
                    break
            
            if not public_key:
                raise RuntimeError("Could not extract public key from master key file")
            
            # Create initial SOPS file - first create the file, then encrypt it
            initial_json = {
                "managed_by_sops_secrets": True,
                "created_at": int(time.time() * 1000)
            }
            sops_file_path.write_text(json.dumps(initial_json, indent=2) + "\n")
            
            # Now encrypt the file
            subprocess.run(
                [
                    "sops",
                    "-e",
                    "-i",
                    "--age",
                    public_key,
                    str(sops_file_path),
                ],
                check=True,
                capture_output=True,
            )
        
        return master_key_path, sops_file_path, secrets_dir
    
    def start_server(self) -> subprocess.Popen:
        """Start the server process and return it."""
        # Start the server process
        env = os.environ.copy()
        env.update({
            "SERVER_PORT": str(self.server_port),
            "SOPS_FILE_PATH": str(self.sops_file_path),
            "SOPS_MASTER_KEY_PATH": str(self.master_key_path),
            "SECRETS_DIR": str(self.secrets_dir),
            "DOCKER_VALIDATION_LEVEL": "none",  # Disable Docker validation
            "SOPS_TIMEOUT_SECONDS": "30",  # Increase SOPS timeout to 30 seconds
            "RUST_LOG": "debug",  # Enable debug logging to see SOPS commands
        })

        # Create a log file for the server output
        self._server_logfile = open(str(self.test_dir / "server.log"), "w")

        process = subprocess.Popen(
            [str(self.local_binary)],
            env=env,
            stdout=self._server_logfile,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,  # Line buffered
        )

        # Wait for server to start
        time.sleep(2)

        # Check if process is still running
        if process.poll() is not None:
            self._server_logfile.seek(0)
            log_content = self._server_logfile.read() if not self._server_logfile.closed else "(log file closed)"
            raise RuntimeError(
                f"Server failed to start. Exit code: {process.returncode}\n"
                f"Server log output:\n{log_content}"
            )

        self.server_process = process
        return process
    
    def stop_server(self):
        """Stop the server process if it's running."""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                self.server_process.wait()
            finally:
                self.server_process = None
        # Close the log file if open
        if hasattr(self, '_server_logfile') and self._server_logfile and not self._server_logfile.closed:
            self._server_logfile.close()
    
    def get_server_logs(self) -> str:
        """Get the server log content."""
        if hasattr(self, '_server_logfile') and self._server_logfile and not self._server_logfile.closed:
            self._server_logfile.flush()
            self._server_logfile.seek(0)
            return self._server_logfile.read()
        else:
            # Try to read from the log file if it exists
            log_file = self.test_dir / "server.log"
            if log_file.exists():
                return log_file.read_text()
            return "No server logs available"
    
    def copy_logs_to_results(self):
        """Copy server logs and test artifacts to the results directory for debugging."""
        try:
            # Create a unique results subdirectory for this test run
            timestamp = int(time.time())
            test_results_dir = self.results_dir / f"test_run_{timestamp}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
            test_results_dir.mkdir(exist_ok=True)
            
            # Copy server log if it exists
            server_log = self.test_dir / "server.log"
            if server_log.exists():
                shutil.copy2(server_log, test_results_dir / "server.log")
                print(f"📋 Server logs copied to: {test_results_dir / 'server.log'}")
            
            # Copy the entire test directory for complete debugging context
            test_artifacts_dir = test_results_dir / "test_artifacts"
            if self.test_dir.exists():
                shutil.copytree(self.test_dir, test_artifacts_dir, dirs_exist_ok=True)
                print(f"📋 Test artifacts copied to: {test_artifacts_dir}")
            
            # Create a summary file with test environment info
            summary_file = test_results_dir / "test_summary.txt"
            with open(summary_file, 'w') as f:
                f.write(f"Test Run Summary\n")
                f.write(f"================\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
                f.write(f"PID: {os.getpid()}\n")
                f.write(f"Test Directory: {self.test_dir}\n")
                f.write(f"Server Port: {self.server_port}\n")
                f.write(f"Local Binary: {self.local_binary}\n")
                f.write(f"Master Key Path: {self.master_key_path}\n")
                f.write(f"SOPS File Path: {self.sops_file_path}\n")
                f.write(f"Secrets Directory: {self.secrets_dir}\n")
                f.write(f"\nEnvironment Variables:\n")
                f.write(f"  SERVER_PORT: {self.server_port}\n")
                f.write(f"  SOPS_FILE_PATH: {self.sops_file_path}\n")
                f.write(f"  SOPS_MASTER_KEY_PATH: {self.master_key_path}\n")
                f.write(f"  SECRETS_DIR: {self.secrets_dir}\n")
                f.write(f"  DOCKER_VALIDATION_LEVEL: none\n")
            
            print(f"📋 Test summary written to: {summary_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to copy logs to results directory: {e}")

    def cleanup(self):
        """Clean up the test environment."""
        # Copy logs before stopping the server
        self.copy_logs_to_results()
        
        self.stop_server()
        # The temp_dir fixture will handle cleaning up the directory


# Fixtures
@pytest.fixture(scope="session")
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for the test session."""
    # Check if we should preserve the temp directory for debugging
    preserve_temp = os.environ.get("PRESERVE_TEMP_DIR", "").lower() in ("1", "true", "yes")
    
    if preserve_temp:
        # Create a persistent temp directory for debugging
        temp_dir = Path(f"/tmp/sops_test_debug_{int(time.time())}_{os.getpid()}")
        temp_dir.mkdir(exist_ok=True)
        print(f"🔍 DEBUG MODE: Preserving temp directory at: {temp_dir}")
        print(f"🔍 To clean up manually, run: rm -rf {temp_dir}")
        yield temp_dir
    else:
        # Normal cleanup behavior
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)


@pytest.fixture(scope="session")
def server_port() -> int:
    """Port for the test server."""
    return 3103  # Use different port to avoid conflicts


@pytest.fixture(scope="session")
def server_url(server_port: int) -> str:
    """URL for the test server."""
    return f"http://localhost:{server_port}"


@pytest.fixture(scope="session")
def local_binary() -> Path:
    """Get the path to the local server binary."""
    # Get the path relative to the core directory (parent of tests directory)
    binary = Path(__file__).parent.parent.parent / "target/debug/sops-secrets-server-local"
    if not binary.exists():
        raise RuntimeError(
            f"Local server binary not found at {binary}. "
            "Run: cargo build --features insecure_mode"
        )
    return binary


@pytest.fixture
def integration_helper(temp_dir: Path, server_port: int, local_binary: Path) -> Generator[IntegrationTestHelper, None, None]:
    """
    Create an IntegrationTestHelper for each test.
    
    This fixture creates a new test environment for each test, ensuring
    complete isolation between tests.
    """
    helper = IntegrationTestHelper(temp_dir, server_port, local_binary)
    
    # Start the server
    helper.start_server()
    
    yield helper
    
    # Cleanup
    helper.cleanup()


@pytest_asyncio.fixture
async def client(server_url: str, temp_dir: Path) -> AsyncGenerator[SopsClient, None]:
    """Create a SOPS client for testing."""
    # Create a unique client directory for this test
    client_dir = temp_dir / f"client_{int(time.time())}"
    client_dir.mkdir(exist_ok=True)
    
    client = SopsClient(
        server_url=server_url,
        base_directory=str(client_dir),
        timeout=10,
    )
    
    try:
        await client.connect()
        yield client
    finally:
        await client.close()


@pytest.fixture
def test_secret_name() -> str:
    """Generate a unique test secret name."""
    return f"test_secret_{int(time.time())}_{os.getpid()}"


@pytest.fixture
def test_secret_value() -> str:
    """Test secret value."""
    return f"test_secret_value_{int(time.time())}"


@pytest.fixture
def test_client_name() -> str:
    """Test client name for local mode."""
    return f"test-client-{int(time.time())}" 