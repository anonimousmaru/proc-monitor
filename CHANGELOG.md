# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-13

### Added
- **Dual-mode support**: Choose between `threshold` and `top_n` modes
- `top_n` mode: Track the highest N processes by CPU/RAM usage
- New configuration options: `mode` and `top_n`

### Changed
- Refactored monitoring logic into separate functions for each mode
- Improved console output formatting

---

## [1.0.0] - 2026-01-13

### Added
- Initial release of Proc-Monitor
- CPU usage monitoring with configurable threshold
- RAM usage monitoring with configurable threshold
- Systemd service detection via cgroup parsing
- Parent process chain tracking
- JSON configuration file support (`config.json`)
- JSON report generation with service-based summaries
- Real-time console output with detailed process information
- English usage guide (`USAGE_EN.md`)
- Turkish usage guide (`USAGE_TR.md`)

### Features
- Zero external dependencies - uses only Python standard library
- Direct `/proc` filesystem reading for maximum compatibility
- Configurable check intervals for catching short-lived processes
- Graceful shutdown with CTRL+C and automatic report saving
