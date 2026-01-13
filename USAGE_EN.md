# Proc-Monitor Usage Guide

## Overview

Proc-Monitor is a lightweight Linux process monitoring tool that detects high CPU/RAM consuming processes and identifies which services or programs spawned them. It requires **no external dependencies** - only Python 3.6+.

## Quick Start

### One-Line Install & Run
```bash
curl -sL https://raw.githubusercontent.com/cagatayuresin/proc-monitor/main/proc_monitor.py | sudo python3 -
```

### Download and Run
```bash
# Download
wget https://raw.githubusercontent.com/cagatayuresin/proc-monitor/main/proc_monitor.py

# Run
sudo python3 proc_monitor.py
```

### Clone Repository
```bash
git clone https://github.com/cagatayuresin/proc-monitor.git
cd proc-monitor
sudo python3 proc_monitor.py
```

## Configuration

Create a `config.json` file in the same directory as `proc_monitor.py`:

```json
{
    "mode": "threshold",
    "top_n": 5,
    "cpu_threshold": 50.0,
    "ram_threshold": 10.0,
    "check_interval": 0.3,
    "output_file": "resource_report.json",
    "track_cpu": true,
    "track_ram": true
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mode` | string | "threshold" | Detection mode: `"threshold"` or `"top_n"` |
| `top_n` | int | 5 | Number of top processes to track (only for `top_n` mode) |
| `cpu_threshold` | float | 50.0 | CPU usage percentage to trigger detection (only for `threshold` mode) |
| `ram_threshold` | float | 10.0 | RAM usage percentage to trigger detection (only for `threshold` mode) |
| `check_interval` | float | 0.3 | Seconds between each check (lower = catch more short-lived processes) |
| `output_file` | string | "resource_report.json" | Path to save the report |
| `track_cpu` | bool | true | Enable CPU monitoring |
| `track_ram` | bool | true | Enable RAM monitoring |

### Modes

**Threshold Mode** (`"mode": "threshold"`):
- Captures ALL processes that exceed the CPU or RAM thresholds
- Best for catching any process that crosses a limit

**Top-N Mode** (`"mode": "top_n"`):
- Captures the top N processes by CPU and RAM usage
- Best for continuous monitoring of highest resource consumers

If `config.json` doesn't exist, default values are used.

## Running

### Basic Usage
```bash
sudo python3 proc_monitor.py
```

> **Note:** Root privileges are recommended for accessing all process information.

### Stop Monitoring
Press `CTRL+C` to stop monitoring and generate the report.

## Understanding the Output

### Real-time Console Output
```
[2024-01-15 10:30:45] [CPU] stress (PID:12345)
    CPU: 98.5% | RAM: 0.3% (12.4 MB)
    Service: stress-test.service
    User: root
    Chain: stress(12345) -> bash(12300) -> systemd(1)
    Cmd: /usr/bin/stress --cpu 1
```

- **Timestamp**: When the process was detected
- **Trigger**: What triggered detection (CPU, RAM, or both)
- **Service**: The systemd service or scope that owns the process
- **Chain**: Parent process chain (process -> parent -> grandparent)
- **Cmd**: The command line that started the process

### Report File (JSON)

The report includes:
- **config**: Configuration used during monitoring
- **summary**: Aggregated data by service
- **events**: All individual detection events

Example summary section:
```json
{
  "summary": {
    "total_events": 150,
    "by_service": {
      "apache2.service": {
        "count": 100,
        "processes": [...]
      }
    }
  }
}
```

## Use Cases

### Finding Short-Lived CPU Hogs
```json
{
    "cpu_threshold": 30.0,
    "check_interval": 0.1,
    "track_ram": false
}
```

### Memory Leak Detection
```json
{
    "ram_threshold": 5.0,
    "check_interval": 1.0,
    "track_cpu": false
}
```

### Comprehensive Monitoring
```json
{
    "cpu_threshold": 40.0,
    "ram_threshold": 8.0,
    "check_interval": 0.5
}
```

## Troubleshooting

### "Permission Denied" Errors
Run with `sudo` for full access:
```bash
sudo python3 proc_monitor.py
```

### "/proc filesystem not found"
This tool only works on Linux systems with the `/proc` filesystem.

### Processes Disappearing Too Fast
Lower the `check_interval` in config:
```json
{
    "check_interval": 0.1
}
```

## How It Works

1. Reads `/proc` filesystem directly (no external libraries)
2. Calculates CPU usage by comparing process ticks between intervals
3. Gets memory from `/proc/<pid>/statm`
4. Finds parent services from `/proc/<pid>/cgroup`
5. Builds parent chain by following PPIDs

## Requirements

- **OS**: Linux (Ubuntu, Debian, CentOS, etc.)
- **Python**: 3.6 or higher
- **Privileges**: Root recommended (can run without, but limited access)
