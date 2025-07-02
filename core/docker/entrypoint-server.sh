#!/bin/sh

# Try to fix Docker socket permissions (ignore errors if not present or not allowed)
if [ -S /var/run/docker.sock ]; then
    chown root:docker /var/run/docker.sock 2>/dev/null || true
    chmod 660 /var/run/docker.sock 2>/dev/null || true
fi

# Check if we need to switch to appuser
if [ "$(id -u)" = "0" ] && [ -n "$(getent passwd appuser)" ]; then
    # We're root and appuser exists, switch to appuser
    exec setpriv --reuid=appuser --regid=appuser --init-groups /usr/local/bin/sops-secrets-server "$@"
else
    # Run as current user
    exec /usr/local/bin/sops-secrets-server "$@"
fi 