"""
SOPS Secrets Manager Python Client Package

A Python client for connecting to the SOPS secrets server via HTTP.
"""

from .sops_client import (
    SopsClient,
    SopsClientError,
    SopsClientConfigError,
    SopsClientConnectionError,
    SopsClientAuthError,
    SopsClientSecretError,
    get_secret,
    set_secret,
    health_check,
)

__version__ = "1.0.0"
__all__ = [
    "SopsClient",
    "SopsClientError",
    "SopsClientConfigError", 
    "SopsClientConnectionError",
    "SopsClientAuthError",
    "SopsClientSecretError",
    "get_secret",
    "set_secret", 
    "health_check",
] 