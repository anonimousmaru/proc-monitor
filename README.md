# Proc-Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-Linux-green.svg)](https://www.linux.org/)

**Proc-Monitor** is a lightweight Linux process monitoring tool that detects high CPU/RAM consuming processes and identifies their parent services. Perfect for catching those sneaky short-lived processes that disappear before you can investigate!

## ✨ Features

- 🚀 **Zero Dependencies** - Uses only Python standard library
- 📊 **CPU & RAM Monitoring** - Track both resource types simultaneously
- 🔍 **Service Detection** - Identifies which systemd service spawned the process
- 🔗 **Parent Chain** - Shows the complete process ancestry
- ⚡ **Fast Detection** - Configurable intervals as low as 100ms
- 📝 **JSON Reports** - Detailed reports with service-based summaries

## 🚀 Quick Start

### One-Line Run (No Installation)
```bash
curl -sL https://raw.githubusercontent.com/cagatayuresin/proc-monitor/main/proc_monitor.py | sudo python3 -
```

### Download & Run
```bash
wget https://raw.githubusercontent.com/cagatayuresin/proc-monitor/main/proc_monitor.py
sudo python3 proc_monitor.py
```

### Clone Repository
```bash
git clone https://github.com/cagatayuresin/proc-monitor.git
cd proc-monitor
sudo python3 proc_monitor.py
```

## 📋 Requirements

- **OS**: Linux (Ubuntu, Debian, CentOS, RHEL, etc.)
- **Python**: 3.6 or higher
- **Privileges**: Root recommended for full access

## ⚙️ Configuration

Create `config.json` in the same directory:

```json
{
    "cpu_threshold": 50.0,
    "ram_threshold": 10.0,
    "check_interval": 0.3,
    "output_file": "resource_report.json",
    "track_cpu": true,
    "track_ram": true
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `cpu_threshold` | 50.0 | CPU % to trigger detection |
| `ram_threshold` | 10.0 | RAM % to trigger detection |
| `check_interval` | 0.3 | Seconds between checks |
| `output_file` | resource_report.json | Report file path |
| `track_cpu` | true | Enable CPU tracking |
| `track_ram` | true | Enable RAM tracking |

## 📖 Example Output

```
[2024-01-15 10:30:45] [CPU] stress (PID:12345)
    CPU: 98.5% | RAM: 0.3% (12.4 MB)
    Service: stress-test.service
    User: root
    Chain: stress(12345) -> bash(12300) -> systemd(1)
    Cmd: /usr/bin/stress --cpu 1
```

## 📚 Documentation

- [English Usage Guide](USAGE_EN.md)
- [Türkçe Kullanım Kılavuzu](USAGE_TR.md)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the need to catch short-lived resource-hungry processes
- Built for system administrators and developers who need quick diagnostics

---

Made with ❤️ by [Çağatay Üresin](https://github.com/cagatayuresin)
