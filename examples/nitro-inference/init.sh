#!/bin/bash
# PID1 wrapper for Nitro Enclave
# Ensures proper signal handling and NSM device access
exec /app/enclave-server --model-dir /model "$@"
