# XLScanner 🔍

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

**XLScanner** is a professional, feature-rich network port scanner designed for security professionals and network administrators. Built with Python, it offers fast multi-threaded scanning, service detection, and comprehensive reporting capabilities.

```
          /$$                                                                      
          | $$                                                                      
 /$$   /$$| $$  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
|  $$ /$$/| $$ /$$_____/ /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
 \  $$$$/ | $$|  $$$$$$ | $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
  >$$  $$ | $$ \____  $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
 /$$/\  $$| $$ /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
|__/  \__/|__/|_______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
```

## ✨ Features

- 🚀 **Fast Multi-threaded Scanning** - Scan thousands of ports in seconds
- 🎯 **Service Detection** - Identify services running on open ports
- 📊 **Latency Analysis** - Measure and analyze response times
- 📝 **JSON Export** - Save results in structured format
- 🔄 **Real-time Monitoring** - Monitor specific ports for status changes
- 🌐 **DNS Lookup** - Built-in DNS resolution tools
- 📜 **Command History** - Track and replay previous scans
- 🎨 **Colored Output** - Easy-to-read terminal interface
- ⚡ **Rate Limiting** - Control scan speed to avoid detection
- 🔍 **Banner Grabbing** - Retrieve service banners and headers

## 🛠️ Installation

### Prerequisites

- Python 3.7 or higher
- Standard library only (no external dependencies!)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/xlscanner.git

# Navigate to directory
cd xlscanner

# Make executable (Linux/macOS)
chmod +x xlscanner.py

# Run
python xlscanner.py
```

## 🚀 Quick Start

### Basic Scan
```bash
scan scanme.nmap.org -p 1-1000
```

### Fast Scan (Common Ports)
```bash
scan 192.168.1.1 -fast
```

### Advanced Scan with Service Detection
```bash
scan example.com -p 1-65535 -t 500 -sV -A -o results.json
```

## 📖 Usage Guide

### Command Syntax

```
scan <target> -p <port-range> [options]
```

### Scan Options

| Option | Description | Example |
|--------|-------------|---------|
| `-p <range>` | Port range to scan | `-p 1-1000` |
| `-fast` | Scan common ports only | `-fast` |
| `-t <num>` | Number of threads | `-t 500` |
| `-timeout <sec>` | Connection timeout | `-timeout 2.0` |
| `-delay <sec>` | Delay between ports | `-delay 0.1` |
| `-sV` | Service version detection | `-sV` |
| `-A` | Aggressive scan (service + latency) | `-A` |
| `-v` | Verbose output | `-v` |
| `-vv` | Very verbose (show closed ports) | `-vv` |
| `-o <file>` | Save results to file | `-o scan.json` |
| `-sU` | UDP scan (experimental) | `-sU` |
| `-sT` | TCP connect scan (default) | `-sT` |

### Additional Commands

| Command | Description |
|---------|-------------|
| `monitor <target> -p <port>` | Monitor port for changes |
| `dns <hostname>` | Perform DNS lookup |
| `report` | Generate report from last scan |
| `history` | Show command history |
| `help` | Display help information |
| `clear` | Clear screen |
| `exit` | Exit application |

## 💡 Examples

### 1. Scan Web Server Ports
```bash
scan example.com -p 80-443 -sV
```

### 2. Full Port Scan with High Speed
```bash
scan 192.168.1.100 -p 1-65535 -t 1000 -timeout 0.5
```

### 3. Scan and Export Results
```bash
scan target.com -p 1-1000 -A -o target_scan.json
```

### 4. Monitor Critical Service
```bash
monitor production-server.com -p 443 -interval 5
```

### 5. Stealthy Scan with Rate Limiting
```bash
scan target.com -p 1-1000 -t 50 -delay 0.5 -timeout 3
```

## 📊 Output Format

### Console Output
```
Target: scanme.nmap.org (45.33.32.156)
Ports: 1000  Threads: 200  Timeout: 1.0s
Scan Type: TCP

Open Ports (5):
PORT     SERVICE              LATENCY        
--------------------------------------------------
22       ssh                  45.23ms
80       http                 42.18ms
443      https                43.91ms
9929     unknown              48.76ms
31337    unknown              52.44ms

Closed/Filtered: 995
Total Scanned: 1000
```

### JSON Export
```json
{
  "target": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "timestamp": "2025-01-16 15:30:45",
  "open": [
    {
      "port": 22,
      "service": "ssh",
      "latency": 45.23
    }
  ],
  "closed_count": 995,
  "latency": {
    "22": 45.23,
    "80": 42.18
  }
}
```

## ⚙️ Configuration

XLScanner creates a configuration file (`xlscanner_config.json`) on first run:

```json
{
  "default_threads": 200,
  "default_timeout": 1.0,
  "save_history": true,
  "verbose": false
}
```

## 🎯 Performance Tips

1. **Increase threads** for faster scans: `-t 500` or `-t 1000`
2. **Reduce timeout** for known-responsive hosts: `-timeout 0.5`
3. **Use -fast** for quick reconnaissance
4. **Add delays** for stealth: `-delay 0.1`
5. **Target specific ports** instead of full range scans

## 🔒 Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only.

- ✅ Only scan systems you own or have explicit permission to test
- ✅ Respect network policies and terms of service
- ✅ Use responsibly and ethically
- ❌ Unauthorized scanning may be illegal in your jurisdiction
- ❌ The authors are not responsible for misuse

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**xloria**

- GitHub: [@xloria](https://github.com/xloria)

## 🌟 Acknowledgments

- Inspired by classic network scanning tools
- Built for the security community
- Thanks to all contributors

## 📞 Support

If you encounter any issues or have questions:

- Open an [Issue](https://github.com/yourusername/xlscanner/issues)
- Check existing [Discussions](https://github.com/yourusername/xlscanner/discussions)

---

**Made with ❤️ by xloria**

*Scan responsibly, stay secure.*