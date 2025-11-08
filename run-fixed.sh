#!/usr/bin/env bash

echo "🚀 Starting eBPF Micro-Segmentation System..."

# Check root
if [ "$(id -u)" -ne 0 ]; then
   echo "⚠️  Run with sudo"
   exit 1
fi

# Kill existing processes
pkill -f "collector/main.go" 2>/dev/null || true
pkill -f "streamlit run app.py" 2>/dev/null || true
pkill -f "agent/main.go" 2>/dev/null || true

sleep 2

# Get the actual user (not root)
ACTUAL_USER=$(logname 2>/dev/null || echo $SUDO_USER)
USER_HOME=$(eval echo ~$ACTUAL_USER)

echo "📡 Starting collector..."
cd collector
go run main.go > /tmp/collector.log 2>&1 &
COLLECTOR_PID=$!
cd ..

sleep 5

echo "🖥️  Starting UI..."
cd ui
# Run as actual user with venv
su - $ACTUAL_USER -c "cd $(pwd) && source venv/bin/activate && streamlit run app.py --server.port 8501 --server.headless true" > /tmp/ui.log 2>&1 &
UI_PID=$!
cd ..

sleep 3

echo "🔍 Starting eBPF agent..."
cd agent
go run main.go --mode observe --collector http://localhost:8080/api/events 2>&1 &
AGENT_PID=$!
cd ..

echo ""
echo "✅ All components started!"
echo ""
echo "📊 Dashboard: http://localhost:8501"
echo "📡 Collector API: http://localhost:8080"
echo ""
echo "To view logs:"
echo "  tail -f /tmp/collector.log"
echo "  tail -f /tmp/ui.log"
echo ""
echo "To stop:"
echo "  sudo pkill -f 'go run main.go'"
echo "  pkill -f streamlit"
echo ""
echo "Press Ctrl+C to stop (may need to kill manually)"

# Simple wait
tail -f /tmp/collector.log /tmp/ui.log &
wait