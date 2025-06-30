#!/usr/bin/env python3
"""
Integration Test Runner for SOPS Secrets Manager

This script runs comprehensive end-to-end tests to verify the complete
functionality of the SOPS secrets management system.
"""

import asyncio
import json
import os
import sys
import time
import traceback
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
import docker
import yaml

from test_helpers import (
    TestHelper, 
    SecretManager, 
    DockerHelper, 
    AgeKeyManager,
    TestResult,
    TestStatus
)
from test_scenarios import TestScenarios


class IntegrationTestRunner:
    """Main test runner that orchestrates all integration tests."""
    
    def __init__(self):
        self.server_url = os.getenv('SOPS_SERVER_URL', 'http://localhost:3000')
        self.master_key_path = os.getenv('MASTER_KEY_PATH', '/run/secrets/master_key.age')
        self.sops_file_path = os.getenv('SOPS_FILE_PATH', '/run/secrets/secrets.yaml')
        self.public_key_path = os.getenv('PUBLIC_KEY_PATH', '/run/secrets/public-key.txt')
        self.private_key_path = os.getenv('PRIVATE_KEY_PATH', '/run/secrets/private-key.txt')
        
        self.test_results: List[TestResult] = []
        self.helper = TestHelper(self.server_url)
        self.secret_manager = SecretManager(self.sops_file_path, self.master_key_path)
        self.docker_helper = DockerHelper()
        self.age_manager = AgeKeyManager()
        
    async def run_all_tests(self) -> bool:
        """Run all integration tests and return overall success status."""
        print("🚀 Starting SOPS Secrets Manager Integration Tests")
        print(f"📅 Test started at: {datetime.now().isoformat()}")
        print(f"🌐 Server URL: {self.server_url}")
        print("=" * 80)
        
        # Generate fresh test files for this test run
        await self._generate_fresh_test_files()
        
        # Initialize test environment
        await self._setup_test_environment()
        
        # Run test suites
        test_suites = [
            ("Server Health & Configuration", self._test_server_health),
            ("Secret Management", self._test_secret_management),
            ("Access Control", self._test_access_control),
            ("Docker Integration", self._test_docker_integration),
            ("Security Features", self._test_security_features),
            ("Error Handling", self._test_error_handling),
            ("Exporter Functionality", self._test_exporter),
            ("CLI Functionality", self._test_cli_functionality),
            ("Performance & Reliability", self._test_performance),
        ]
        
        all_passed = True
        
        for suite_name, test_func in test_suites:
            print(f"\n📋 Running Test Suite: {suite_name}")
            print("-" * 60)
            
            try:
                suite_passed = await test_func()
                if not suite_passed:
                    all_passed = False
            except Exception as e:
                print(f"❌ Test suite '{suite_name}' failed with exception: {e}")
                traceback.print_exc()
                all_passed = False
        
        # Generate test report
        await self._generate_test_report()
        
        # Clean up test files
        await self._cleanup_test_files()
        
        return all_passed
    
    async def _generate_fresh_test_files(self):
        """Generate fresh master key and secrets files for this test run."""
        print("🔧 Generating fresh test files for this test run...")
        
        try:
            # Generate new age master key
            print("🔑 Generating new age master key...")
            result = subprocess.run(
                ["age-keygen", "-o", self.master_key_path],
                capture_output=True,
                text=True,
                check=True
            )
            print("✅ Generated new age master key")
            
            # Extract public key for SOPS configuration
            result = subprocess.run(
                ["age-keygen", "-y", self.master_key_path],
                capture_output=True,
                text=True,
                check=True
            )
            public_key = result.stdout.strip()
            print(f"🔑 Extracted public key: {public_key[:20]}...")
            
            # Create fresh test secrets
            print("📝 Creating fresh test secrets...")
            test_secrets = {
                "database": {
                    "password": f"test-db-password-{int(time.time())}",
                    "host": "localhost",
                    "port": 5432,
                    "name": "test_db"
                },
                "api": {
                    "key": f"test-api-key-{int(time.time())}",
                    "secret": f"test-api-secret-{int(time.time())}",
                    "endpoint": "https://api.test.com"
                },
                "redis": {
                    "password": f"test-redis-password-{int(time.time())}",
                    "host": "localhost",
                    "port": 6379
                },
                "jwt": {
                    "secret": f"test-jwt-secret-{int(time.time())}",
                    "expiry": 3600
                },
                "test_data": {
                    "string_value": "test-string",
                    "number_value": 42,
                    "boolean_value": True,
                    "list_value": ["item1", "item2", "item3"],
                    "nested": {
                        "key1": "value1",
                        "key2": "value2"
                    }
                }
            }
            
            # Write unencrypted secrets
            with open(self.sops_file_path, 'w') as f:
                yaml.dump(test_secrets, f, default_flow_style=False, sort_keys=False)
            
            # Create SOPS configuration
            sops_config = {
                "creation_rules": [{
                    "age": public_key
                }]
            }
            
            sops_config_path = Path(self.sops_file_path).parent / ".sops.yaml"
            with open(sops_config_path, 'w') as f:
                yaml.dump(sops_config, f)
            
            # Encrypt the secrets file with SOPS
            print("🔒 Encrypting secrets with SOPS...")
            result = subprocess.run(
                ["sops", "-e", "-i", self.sops_file_path],
                capture_output=True,
                text=True,
                check=True
            )
            
            print("✅ Successfully generated fresh test files")
            print(f"   Master key: {self.master_key_path}")
            print(f"   Encrypted secrets: {self.sops_file_path}")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate test files: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            raise
        except Exception as e:
            print(f"❌ Failed to generate test files: {e}")
            raise
    
    async def _cleanup_test_files(self):
        """Clean up test files after test run."""
        print("🧹 Cleaning up test files...")
        
        try:
            # Remove test files
            test_files = [
                self.master_key_path,
                self.sops_file_path,
                Path(self.sops_file_path).parent / ".sops.yaml"
            ]
            
            for file_path in test_files:
                if Path(file_path).exists():
                    Path(file_path).unlink()
                    print(f"🗑️  Removed {file_path}")
            
            print("✅ Test files cleaned up")
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to clean up some test files: {e}")
    
    async def _setup_test_environment(self):
        """Set up the test environment."""
        print("🔧 Setting up test environment...")
        
        # Wait for server to be ready
        await self._wait_for_server()
        
        # Initialize test secrets
        await self._initialize_test_secrets()
        
        # Verify Docker environment
        await self._verify_docker_environment()
        
        print("✅ Test environment setup complete")
    
    async def _wait_for_server(self, max_attempts: int = 30):
        """Wait for the server to be ready."""
        print("⏳ Waiting for server to be ready...")
        
        for attempt in range(max_attempts):
            try:
                response = requests.get(f"{self.server_url}/health", timeout=5)
                if response.status_code == 200:
                    health_data = response.json()
                    if all(health_data.get('checks', {}).values()):
                        print("✅ Server is ready and healthy")
                        return
                    else:
                        print(f"⚠️  Server health check failed: {health_data}")
                else:
                    print(f"⚠️  Server health check returned {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"⏳ Server not ready yet (attempt {attempt + 1}/{max_attempts}): {e}")
            
            await asyncio.sleep(2)
        
        raise Exception("Server failed to become ready within expected time")
    
    async def _initialize_test_secrets(self):
        """Initialize test secrets in the SOPS file."""
        print("🔐 Initializing test secrets...")
        
        # Create test secrets with proper access control
        test_secrets = {
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
            }
        }
        
        for secret_name, secret_config in test_secrets.items():
            await self.secret_manager.create_secret(
                secret_name,
                secret_config["value"],
                secret_config["owner"],
                secret_config["readers"],
                secret_config["writers"]
            )
        
        print(f"✅ Initialized {len(test_secrets)} test secrets")
    
    async def _verify_docker_environment(self):
        """Verify Docker environment is properly configured."""
        print("🐳 Verifying Docker environment...")
        
        # Check if test containers are running
        containers = self.docker_helper.get_containers()
        expected_containers = [
            "sops-secrets-server-test",
            "authorized-client-test",
            "unauthorized-client-test",
            "untrusted-client-test",
            "exporter-client-test"
        ]
        
        running_containers = [c.name for c in containers if c.status == "running"]
        missing_containers = [name for name in expected_containers if name not in running_containers]
        
        if missing_containers:
            print(f"⚠️  Missing containers: {missing_containers}")
        else:
            print("✅ All test containers are running")
    
    async def _test_server_health(self) -> bool:
        """Test server health and configuration."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_server_health()
    
    async def _test_secret_management(self) -> bool:
        """Test secret management functionality."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_secret_management()
    
    async def _test_access_control(self) -> bool:
        """Test access control and authorization."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_access_control()
    
    async def _test_docker_integration(self) -> bool:
        """Test Docker integration and container validation."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_docker_integration()
    
    async def _test_security_features(self) -> bool:
        """Test security features like rate limiting and encryption."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_security_features()
    
    async def _test_error_handling(self) -> bool:
        """Test error handling and edge cases."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_error_handling()
    
    async def _test_exporter(self) -> bool:
        """Test exporter functionality."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_exporter()
    
    async def _test_cli_functionality(self) -> bool:
        """Test CLI functionality."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_cli_functionality()
    
    async def _test_performance(self) -> bool:
        """Test performance and reliability."""
        scenarios = TestScenarios(self.helper, self.secret_manager, self.docker_helper, self.age_manager)
        return await scenarios.test_performance()
    
    async def _generate_test_report(self):
        """Generate a comprehensive test report."""
        print("\n" + "=" * 80)
        print("📊 TEST REPORT")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r.status == TestStatus.PASSED])
        failed_tests = len([r for r in self.test_results if r.status == TestStatus.FAILED])
        skipped_tests = len([r for r in self.test_results if r.status == TestStatus.SKIPPED])
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Skipped: {skipped_tests} ⏭️")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.test_results:
                if result.status == TestStatus.FAILED:
                    print(f"  - {result.name}: {result.error}")
        
        # Save detailed report to file
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "server_url": self.server_url,
            "summary": {
                "total": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "skipped": skipped_tests
            },
            "results": [result.to_dict() for result in self.test_results]
        }
        
        with open("/tmp/integration_test_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: /tmp/integration_test_report.json")


async def main():
    """Main entry point."""
    runner = IntegrationTestRunner()
    
    try:
        success = await runner.run_all_tests()
        if success:
            print("\n🎉 All integration tests passed!")
            sys.exit(0)
        else:
            print("\n💥 Some integration tests failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Test runner failed with exception: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main()) 