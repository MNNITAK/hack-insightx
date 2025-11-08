#!/usr/bin/env bash
set -e

echo "🚀 Setting up eBPF Micro-Segmentation System..."

# Require root for eBPF/system installs
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  This script needs root privileges for eBPF setup"
   echo "Run: sudo ./setup.sh"
   exit 1
fi

# Identify invoking user (when run via sudo)
INVOKING_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
echo "Running as root; project files will be prepared for user: $INVOKING_USER"

# Check Ubuntu version
. /etc/os-release
echo "📋 Detected: $PRETTY_NAME"

# Install required packages (ensure python3-venv is present)
echo "📦 Installing dependencies..."
apt-get update
apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    golang-go \
    python3 \
    python3-pip \
    python3-venv \
    make \
    gcc \
    sqlite3

# Install Go dependencies for agent
echo "🔧 Setting up eBPF agent..."
cd agent
go mod init ebpf-agent >/dev/null 2>&1 || true
go get github.com/cilium/ebpf@latest || true
go mod tidy || true
cd ..

# Install Go dependencies for collector
echo "🔧 Setting up collector..."
cd collector
go mod init ebpf-collector >/dev/null 2>&1 || true
go get github.com/gin-gonic/gin@latest || true
go get github.com/mattn/go-sqlite3@latest || true
go mod tidy || true
cd ..

# Install Python dependencies for UI inside a venv owned by the invoking user
echo "🔧 Setting up UI..."
cd ui

# Helper to run commands as the invoking non-root user (when available)
run_as_user() {
  if [ "$INVOKING_USER" != "root" ]; then
    sudo -u "$INVOKING_USER" -- "$@"
  else
    "$@"
  fi
}

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment at ui/.venv (owner: $INVOKING_USER)"
    run_as_user python3 -m venv .venv
fi

# Upgrade packaging tools and install requirements using the venv's pip as the invoking user
run_as_user .venv/bin/python -m pip install --upgrade pip setuptools wheel
run_as_user .venv/bin/pip install -r requirements.txt

cd ..

# Compile eBPF program
echo "🏗️  Compiling eBPF program..."
cd agent
make || true
cd ..

# Make scripts executable
chmod +x run.sh

echo "✅ Setup complete!"
echo ""
echo "To run the system (as root):"
echo "  sudo ./run.sh"