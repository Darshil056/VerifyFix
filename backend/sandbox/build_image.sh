#!/bin/bash
set -e

echo "======================================================="
echo "Building VerifyFix Multi-Runtime Sandbox Docker Image"
echo "(Python 3.11 + Node.js 20 LTS + Bash)"
echo "======================================================="

cd "$(dirname "$0")"
docker build -t verifyfix-sandbox:latest .

echo ""
echo "[SUCCESS] verifyfix-sandbox:latest successfully built!"

