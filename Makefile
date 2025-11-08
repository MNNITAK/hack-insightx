.PHONY: all setup build run clean test

all: setup build

setup:
	@echo "🔧 Running setup..."
	@sudo ./setup.sh

build:
	@echo "🏗️ Building eBPF agent..."
	@cd agent && make

run:
	@echo "🚀 Starting system..."
	@sudo ./run.sh

clean:
	@echo "🧹 Cleaning up..."
	@cd agent && make clean
	@rm -f collector/events.db
	@rm -f collector/ebpf-collector
	@rm -f agent/ebpf-agent

test:
	@echo "🧪 Running tests..."
	@bash scripts/test-scenario.sh

traffic:
	@echo "🌐 Generating traffic..."
	@bash scripts/generate-traffic.sh

install:
	@echo "📦 Installing as system service..."
	@sudo bash scripts/install-systemd.sh

help:
	@echo "Available targets:"
	@echo "  setup    - Install dependencies"
	@echo "  build    - Compile eBPF program"
	@echo "  run      - Start all components"
	@echo "  test     - Run test scenarios"
	@echo "  traffic  - Generate test traffic"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install as systemd service"