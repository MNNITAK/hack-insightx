# 🛡️ eBPF Network Micro-Segmentation

Real-time network monitoring with process-level visibility. See every connection, control every process.

## ⚡ Quick Start
```bash
git clone https://github.com/MNNITAK/hack-insightx.git
cd ebpf-microseg
sudo ./setup.sh
./install.sh
```

**Dashboard:** http://localhost:8501


**Demo Video:** https://youtu.be/O0-yEVonWkw?si=QWonGUwVKsWu0fi2

## 🎯 Features

- ✅ Real process names, PIDs, and exe paths
- ✅ Block by process/IP/port with visual rules
- ✅ Live dashboard - no terminal needed
- ✅ Auto-starts on boot
- ✅ Zero cost, fully open source

## 📋 Requirements

- Ubuntu 20.04+ (any Linux)
- Root access
- 512MB RAM minimum

## 🎮 Usage

### View Connections
Dashboard shows every TCP connection with real process info.

### Block a Process
1. Dashboard → Rules tab
2. Add rule: `Process: curl, IP: *, Port: 443, Action: deny`
3. Switch to "enforce" mode
4. Test: `curl https://google.com` → Shows "blocked"

## 🛠️ Commands
```bash
# Start/stop
sudo systemctl start ebpf-collector ebpf-agent ebpf-ui
sudo systemctl stop ebpf-collector ebpf-agent ebpf-ui

# Logs
sudo journalctl -u ebpf-agent -f

# Manual run (3 terminals)
cd collector && sudo go run main.go
cd agent && sudo go run m.go
cd ui && source venv/bin/activate && streamlit run app.py
```

## 🏗️ How It Works

**Agent** (`ss -tunp` + `/proc`) → **Collector** (rules engine) → **Dashboard** (Streamlit)

## 📁 Structure
```
├── agent/       # Network monitor
├── collector/   # API + SQLite
├── ui/          # Dashboard
└── systemd/     # Auto-start services
```

## 🆚 vs Enterprise Tools

| Feature | Enterprise | This |
|---------|-----------|------|
| Cost | $50K+/year | FREE |
| Setup | Weeks | 5 min |
| Process Info | Yes | Yes |
| Open Source | No | Yes |

## 🔒 Production Notes

MVP only. Add: auth, HTTPS, PostgreSQL, rate limiting for production.

## 📝 License

MIT

## 👤 Author

[@AbhishekPandey91](https://github.com/AbhishekPandey91)

---

⭐ Star if useful! |
