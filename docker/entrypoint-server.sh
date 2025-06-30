#!/bin/sh

# Try to fix Docker socket permissions (ignore errors if not present or not allowed)
if [ -S /var/run/docker.sock ]; then
    chown root:docker /var/run/docker.sock 2>/dev/null || true
    chmod 660 /var/run/docker.sock 2>/dev/null || true
fi

# Run the server as appuser
exec su-exec appuser /usr/local/bin/sops-secrets-server "$@" 