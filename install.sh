#!/bin/bash
echo "🚀 Installing eBPF Micro-Segmentation..."
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ebpf-collector ebpf-agent ebpf-ui
sudo systemctl start ebpf-collector
sleep 3
sudo systemctl start ebpf-agent
sudo systemctl start ebpf-ui
echo "✅ Installed! Dashboard: http://localhost:8501"
