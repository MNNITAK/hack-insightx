# 🛡️ eBPF Network Micro-Segmentation

Real-time network monitoring with allow/deny rules.

## ⚡ Quick Start
```bash
git clone https://github.com/YOUR-USERNAME/ebpf-microseg.git
cd ebpf-microseg
sudo ./setup.sh
./install.sh
```

Open: **http://localhost:8501**

## 📋 Requirements

- Ubuntu 20.04+
- Root access
- Go, Python 3, tcpdump

## 🎯 Usage

### Add Block Rule
1. Dashboard → Rules tab
2. Add: `Process: curl, IP: *, Port: 443, Action: deny`
3. Switch to "enforce" mode
4. Test: `curl https://google.com`

### Commands
```bash
# Start
sudo systemctl start ebpf-collector ebpf-agent ebpf-ui

# Stop
sudo systemctl stop ebpf-collector ebpf-agent ebpf-ui

# Logs
sudo journalctl -u ebpf-collector -f
```

## 📁 Structure
```
├── agent/       # Network monitor
├── collector/   # API + Rules
├── ui/          # Dashboard
└── systemd/     # Services
```

## 🔧 Manual Run
```bash
# Terminal 1
cd collector && sudo go run main.go

# Terminal 2
cd agent && sudo go run m.go

# Terminal 3
cd ui && source venv/bin/activate && streamlit run app.py
```

## 📖 How It Works

**Agent** captures TCP connections → **Collector** checks rules → **Dashboard** displays

## �� Contributing

PRs welcome!

## 📄 License

MIT
