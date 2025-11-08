# Install as systemd services (optional)

cat > /etc/systemd/system/ebpf-collector.service << 'EOF'
[Unit]
Description=eBPF Micro-Segmentation Collector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ebpf-microseg/collector
ExecStart=/usr/bin/go run main.go
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ebpf-agent.service << 'EOF'
[Unit]
Description=eBPF Network Agent
After=network.target ebpf-collector.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ebpf-microseg/agent
ExecStart=/usr/bin/go run main.go --mode observe
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "✅ Systemd services created"
echo "Enable with: systemctl enable ebpf-collector ebpf-agent"
echo "Start with: systemctl start ebpf-collector ebpf-agent"