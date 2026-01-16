#!/usr/bin/env python3
"""
XLScanner - Professional Network Port Scanner
A fast, efficient, and feature-rich port scanning tool for security professionals.

Features:
- Multi-threaded TCP/UDP scanning
- Service detection and banner grabbing
- Real-time port monitoring
- Latency analysis and mapping
- Export results (JSON/TXT)
- Network discovery tools
- Comprehensive scan history

Usage: python xlscanner.py
Author: xloria
Version: 2.0.0
License: MIT
"""

import sys
import os
import time
import json
import socket
import threading
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple, Dict, List, Any
from datetime import datetime



class Colors:
    GREEN = "\033[92m"
    WHITE = "\033[97m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


BANNER = r"""
          /$$                                                                      
          | $$                                                                      
 /$$   /$$| $$  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
|  $$ /$$/| $$ /$$_____/ /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
 \  $$$$/ | $$|  $$$$$$ | $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
  >$$  $$ | $$ \____  $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
 /$$/\  $$| $$ /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
|__/  \__/|__/|_______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
"""

AUTHOR_LINE = Colors.GREEN + "------ made by xloria ------" + Colors.RESET
VERSION = "2.0.0"


HISTORY_FILE = "xlscanner_history.json"
CONFIG_FILE = "xlscanner_config.json"


DEFAULT_THREADS = 200
MAX_THREADS = 1000
DEFAULT_TIMEOUT = 1.0
MIN_PORT = 1
MAX_PORT = 65535


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
]

SERVICE_DB: Dict[int, str] = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    515: "printer", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1434: "mssql-monitor",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 3000: "dev-server", 3306: "mysql", 3389: "rdp",
    4369: "erlang", 5000: "upnp", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 6379: "redis", 6667: "irc", 7001: "afs", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "web-dev",
    9090: "web-console", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb-shard", 50000: "db2"
}

class AppState:
    """Global application state"""
    def __init__(self):
        self.language = "EN"
        self.history: List[str] = []
        self.last_scan: Dict[str, Any] = {
            "target": None,
            "ip": None,
            "open": [],
            "closed_count": 0,
            "latency": {},
            "timestamp": None
        }
        self.config: Dict[str, Any] = {
            "default_threads": DEFAULT_THREADS,
            "default_timeout": DEFAULT_TIMEOUT,
            "save_history": True,
            "verbose": False
        }

state = AppState()

def clear_screen():
    """Clear terminal screen"""
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        print("\n" * 50)

def safe_print(*args, **kwargs):
    """Print with encoding error handling"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        try:
            print(*[str(arg).encode('ascii', 'ignore').decode() for arg in args], **kwargs)
        except Exception:
            sys.stdout.write(' '.join(map(str, args)) + '\n')

def safe_input(prompt: str = "") -> str:
    """Input with interrupt handling"""
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        safe_print()
        return ""

def print_banner():
    """Display application banner"""
    clear_screen()
    safe_print(Colors.GREEN + BANNER + Colors.RESET)
    safe_print(AUTHOR_LINE)
    safe_print(Colors.CYAN + f"Version {VERSION}" + Colors.RESET)
    safe_print()

def print_progress(current: int, total: int, prefix: str = "Progress"):
    """Display inline progress bar"""
    if total <= 0:
        return
    
    percent = (current / total) * 100
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    sys.stdout.write(f"\r{Colors.WHITE}{prefix}: [{Colors.GREEN}{bar}{Colors.WHITE}] {percent:6.2f}%{Colors.RESET}")
    sys.stdout.flush()
    
    if current >= total:
        sys.stdout.write('\n')
        sys.stdout.flush()

def get_timestamp() -> str:
    """Get formatted timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_history():
    """Load command history from file"""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    state.history = data[-500:]  
    except Exception:
        state.history = []

def save_history():
    """Save command history to file"""
    if not state.config.get("save_history", True):
        return
    
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(state.history[-500:], f, indent=2)
    except Exception:
        pass

def load_config():
    """Load configuration from file"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    state.config.update(data)
    except Exception:
        pass

def save_config():
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(state.config, f, indent=2)
    except Exception:
        pass


def resolve_host(target: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

def tcp_connect_scan(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    """Perform TCP connect scan on a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        result = sock.connect_ex((ip, port))
        end_time = time.time()
        
        sock.close()
        
        latency = (end_time - start_time) * 1000  
        return (result == 0, latency if result == 0 else None)
    except Exception:
        return (False, None)

def udp_probe(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    """Perform UDP probe on a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        try:
            sock.sendto(b'', (ip, port))
            data, _ = sock.recvfrom(1024)
            end_time = time.time()
            sock.close()
            
            latency = (end_time - start_time) * 1000
            return (True, latency)
        except socket.timeout:
            sock.close()
            return (False, None)
    except Exception:
        return (False, None)

def banner_grab(ip: str, port: int, timeout: float) -> str:
    """Attempt to grab service banner"""
    try:
        
        if port in (80, 8000, 8080, 8443):
            try:
                import http.client
                conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
                conn.request("HEAD", "/")
                response = conn.getresponse()
                server = response.getheader("Server")
                conn.close()
                return server or "http-server"
            except Exception:
                return "http"
        
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            try:
                data = sock.recv(512)
                sock.close()
                if data:
                    banner = data.decode(errors='ignore').strip()
                    return banner[:200] if banner else "no-banner"
            except Exception:
                sock.close()
                return "no-banner"
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return "connection-failed"
    except Exception:
        return "error"


class ScanOptions:
    """Scan configuration options"""
    def __init__(self):
        self.target: str = ""
        self.ports: List[int] = []
        self.threads: int = DEFAULT_THREADS
        self.timeout: float = DEFAULT_TIMEOUT
        self.scan_type: str = "tcp"  
        self.service_detection: bool = False
        self.verbose: bool = False
        self.show_closed: bool = False
        self.collect_latency: bool = False
        self.output_file: Optional[str] = None
        self.rate_limit: float = 0.0

def parse_scan_command(cmd: str) -> Optional[ScanOptions]:
    """Parse scan command and return options"""
    parts = cmd.strip().split()
    
    if len(parts) < 2:
        safe_print(f"{Colors.RED}Usage: scan <target> -p <port-range> [options]{Colors.RESET}")
        return None
    
    options = ScanOptions()
    options.target = parts[1]
    
    i = 2
    try:
        while i < len(parts):
            arg = parts[i]
            
            if arg == "-p":
                port_range = parts[i + 1]
                if "-" in port_range:
                    start, end = map(int, port_range.split("-", 1))
                    options.ports = list(range(start, end + 1))
                else:
                    options.ports = [int(port_range)]
                i += 2
            
            elif arg == "-t":
                options.threads = min(int(parts[i + 1]), MAX_THREADS)
                i += 2
            
            elif arg == "-timeout":
                options.timeout = float(parts[i + 1])
                i += 2
            
            elif arg == "-delay":
                options.rate_limit = float(parts[i + 1])
                i += 2
            
            elif arg == "-fast":
                options.ports = COMMON_PORTS
                i += 1
            
            elif arg == "-sU":
                options.scan_type = "udp"
                i += 1
            
            elif arg == "-sT":
                options.scan_type = "tcp"
                i += 1
            
            elif arg == "-sV":
                options.service_detection = True
                i += 1
            
            elif arg == "-A":
                options.collect_latency = True
                options.service_detection = True
                i += 1
            
            elif arg == "-v":
                options.verbose = True
                i += 1
            
            elif arg == "-vv":
                options.verbose = True
                options.show_closed = True
                i += 1
            
            elif arg == "-o":
                options.output_file = parts[i + 1]
                i += 2
            
            else:
                i += 1
        
        return options
    
    except Exception as e:
        safe_print(f"{Colors.RED}Error parsing options: {e}{Colors.RESET}")
        return None

def perform_scan(cmd: str):
    """Main scan execution function"""
    options = parse_scan_command(cmd)
    if not options:
        return
    
    
    if not options.ports:
        safe_print(f"{Colors.RED}No ports specified. Use -p <port-range> or -fast{Colors.RESET}")
        return
    
    
    ip = resolve_host(options.target)
    if not ip:
        safe_print(f"{Colors.RED}Failed to resolve target: {options.target}{Colors.RESET}")
        return
    
    
    print_banner()
    safe_print(f"{Colors.WHITE}Target: {Colors.GREEN}{options.target} ({ip}){Colors.RESET}")
    safe_print(f"{Colors.WHITE}Ports: {Colors.GREEN}{len(options.ports)}{Colors.RESET}  "
               f"Threads: {Colors.GREEN}{options.threads}{Colors.RESET}  "
               f"Timeout: {Colors.GREEN}{options.timeout}s{Colors.RESET}")
    safe_print(f"{Colors.WHITE}Scan Type: {Colors.GREEN}{options.scan_type.upper()}{Colors.RESET}")
    safe_print()
    
    
    open_ports: List[Tuple[int, Optional[float], str]] = []
    closed_count = 0
    filtered_count = 0
    latency_map: Dict[int, float] = {}
    
    progress_lock = threading.Lock()
    scan_state = {"completed": 0}
    
    def scan_worker(port: int):
        nonlocal open_ports, closed_count, filtered_count
        
        try:
            if options.scan_type == "udp":
                is_open, latency = udp_probe(ip, port, options.timeout)
            else:
                is_open, latency = tcp_connect_scan(ip, port, options.timeout)
            
            with progress_lock:
                scan_state["completed"] += 1
                print_progress(scan_state["completed"], len(options.ports), "Scanning")
            
            if is_open:
                service = SERVICE_DB.get(port, "unknown")
                
                if options.service_detection:
                    banner = banner_grab(ip, port, options.timeout)
                    if banner and banner != "no-banner":
                        service = f"{service} ({banner})"
                
                open_ports.append((port, latency, service))
                
                if latency and options.collect_latency:
                    latency_map[port] = latency
                
                if options.verbose:
                    safe_print(f"\n{Colors.GREEN}[+] {port}/tcp open - {service}{Colors.RESET}")
                    if latency:
                        safe_print(f"    {Colors.CYAN}Latency: {latency:.2f}ms{Colors.RESET}")
            else:
                closed_count += 1
                if options.show_closed:
                    safe_print(f"\n{Colors.YELLOW}[-] {port}/tcp closed{Colors.RESET}")
        
        except Exception as e:
            with progress_lock:
                scan_state["completed"] += 1
                print_progress(scan_state["completed"], len(options.ports), "Scanning")
            
            if options.verbose:
                safe_print(f"\n{Colors.RED}[!] Error scanning port {port}: {e}{Colors.RESET}")
    
    
    try:
        with ThreadPoolExecutor(max_workers=options.threads) as executor:
            futures = []
            for port in options.ports:
                futures.append(executor.submit(scan_worker, port))
                if options.rate_limit > 0:
                    time.sleep(options.rate_limit)
            
            
            for future in as_completed(futures):
                pass
    
    except KeyboardInterrupt:
        safe_print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
    except Exception as e:
        safe_print(f"\n\n{Colors.RED}[!] Scan error: {e}{Colors.RESET}")
    
    
    safe_print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
    safe_print(f"{Colors.BOLD}{Colors.GREEN}Scan Complete{Colors.RESET}")
    safe_print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\n")
    
    open_ports.sort(key=lambda x: x[0])
    
    if open_ports:
        safe_print(f"{Colors.GREEN}Open Ports ({len(open_ports)}):{Colors.RESET}")
        safe_print(f"{Colors.WHITE}{'PORT':<8} {'SERVICE':<20} {'LATENCY':<15}{Colors.RESET}")
        safe_print(f"{Colors.WHITE}{'-'*50}{Colors.RESET}")
        
        for port, latency, service in open_ports:
            lat_str = f"{latency:.2f}ms" if latency else "N/A"
            safe_print(f"{Colors.CYAN}{port:<8}{Colors.RESET} "
                      f"{Colors.WHITE}{service:<20}{Colors.RESET} "
                      f"{Colors.YELLOW}{lat_str:<15}{Colors.RESET}")
    else:
        safe_print(f"{Colors.YELLOW}No open ports found{Colors.RESET}")
    
    safe_print(f"\n{Colors.WHITE}Closed/Filtered: {Colors.RED}{closed_count}{Colors.RESET}")
    safe_print(f"{Colors.WHITE}Total Scanned: {Colors.CYAN}{len(options.ports)}{Colors.RESET}")
    
    if latency_map and options.collect_latency:
        latencies = list(latency_map.values())
        avg_latency = sum(latencies) / len(latencies)
        min_latency = min(latencies)
        max_latency = max(latencies)
        
        safe_print(f"\n{Colors.GREEN}Latency Statistics:{Colors.RESET}")
        safe_print(f"{Colors.WHITE}Average: {Colors.CYAN}{avg_latency:.2f}ms{Colors.RESET}")
        safe_print(f"{Colors.WHITE}Min: {Colors.GREEN}{min_latency:.2f}ms{Colors.RESET}")
        safe_print(f"{Colors.WHITE}Max: {Colors.RED}{max_latency:.2f}ms{Colors.RESET}")
    

    state.last_scan = {
        "target": options.target,
        "ip": ip,
        "open": [{"port": p, "service": s, "latency": l} for p, l, s in open_ports],
        "closed_count": closed_count,
        "latency": latency_map,
        "timestamp": get_timestamp()
    }
    
    if options.output_file:
        try:
            with open(options.output_file, 'w', encoding='utf-8') as f:
                json.dump(state.last_scan, f, indent=2)
            safe_print(f"\n{Colors.GREEN}Results saved to: {options.output_file}{Colors.RESET}")
        except Exception as e:
            safe_print(f"\n{Colors.RED}Failed to save results: {e}{Colors.RESET}")
    
    state.history.append(cmd)
    save_history()
    
    safe_print()
    safe_input(f"{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")

def cmd_monitor(cmd: str):
    """Monitor a single port for status changes"""
    parts = cmd.split()
    
    if len(parts) < 4 or "-p" not in parts:
        safe_print(f"{Colors.RED}Usage: monitor <target> -p <port> [-interval <seconds>]{Colors.RESET}")
        return
    
    target = parts[1]
    port = int(parts[parts.index("-p") + 1])
    interval = 2.0
    
    if "-interval" in parts:
        try:
            interval = float(parts[parts.index("-interval") + 1])
        except Exception:
            pass
    
    ip = resolve_host(target)
    if not ip:
        safe_print(f"{Colors.RED}Failed to resolve target{Colors.RESET}")
        return
    
    print_banner()
    safe_print(f"{Colors.GREEN}Monitoring {target}:{port} (CTRL+C to stop){Colors.RESET}")
    safe_print(f"{Colors.WHITE}Interval: {interval}s{Colors.RESET}\n")
    
    last_status = None
    
    try:
        while True:
            is_open, latency = tcp_connect_scan(ip, port, 1.0)
            status = "OPEN" if is_open else "CLOSED"
            timestamp = get_timestamp()
            
            if status != last_status:
                color = Colors.GREEN if is_open else Colors.RED
                safe_print(f"{Colors.WHITE}[{timestamp}]{Colors.RESET} "
                          f"Status changed: {color}{status}{Colors.RESET}")
                last_status = status
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        safe_print(f"\n{Colors.YELLOW}Monitoring stopped{Colors.RESET}")
    
    safe_input(f"\n{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")

def cmd_dns(cmd: str):
    """DNS lookup"""
    parts = cmd.split()
    
    if len(parts) < 2:
        safe_print(f"{Colors.RED}Usage: dns <hostname>{Colors.RESET}")
        return
    
    host = parts[1]
    
    print_banner()
    safe_print(f"{Colors.WHITE}DNS Lookup: {Colors.CYAN}{host}{Colors.RESET}\n")
    
    ip = resolve_host(host)
    if ip:
        safe_print(f"{Colors.GREEN}Resolved to: {ip}{Colors.RESET}")
    else:
        safe_print(f"{Colors.RED}Resolution failed{Colors.RESET}")
    
    safe_input(f"\n{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")

def cmd_history():
    """Show command history"""
    print_banner()
    safe_print(f"{Colors.GREEN}Command History (Last 50):{Colors.RESET}\n")
    
    history = state.history[-50:]
    for i, cmd in enumerate(history, 1):
        safe_print(f"{Colors.CYAN}{i:3d}.{Colors.RESET} {cmd}")
    
    safe_input(f"\n{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")

def cmd_report():
    """Generate report from last scan"""
    if not state.last_scan.get("target"):
        safe_print(f"{Colors.YELLOW}No scan data available{Colors.RESET}")
        safe_input(f"{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")
        return
    
    print_banner()
    safe_print(f"{Colors.GREEN}Last Scan Report{Colors.RESET}\n")
    safe_print(f"{Colors.WHITE}Target: {Colors.CYAN}{state.last_scan['target']} ({state.last_scan['ip']}){Colors.RESET}")
    safe_print(f"{Colors.WHITE}Timestamp: {Colors.CYAN}{state.last_scan['timestamp']}{Colors.RESET}")
    safe_print(f"{Colors.WHITE}Open Ports: {Colors.GREEN}{len(state.last_scan['open'])}{Colors.RESET}")
    safe_print(f"{Colors.WHITE}Closed Ports: {Colors.RED}{state.last_scan['closed_count']}{Colors.RESET}\n")
    
    filename = f"scan_report_{int(time.time())}.json"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(state.last_scan, f, indent=2)
        safe_print(f"{Colors.GREEN}Report saved to: {filename}{Colors.RESET}")
    except Exception as e:
        safe_print(f"{Colors.RED}Failed to save report: {e}{Colors.RESET}")
    
    safe_input(f"\n{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")

def cmd_help():
    """Display help information"""
    print_banner()
    
    help_text = f"""
{Colors.GREEN}XLScanner - Command Reference{Colors.RESET}

{Colors.CYAN}Basic Scanning:{Colors.RESET}
  scan <target> -p <range>       Scan specified port range
  scan <target> -fast            Scan common ports only
  
{Colors.CYAN}Scan Options:{Colors.RESET}
  -t <threads>                   Number of threads (default: {DEFAULT_THREADS})
  -timeout <seconds>             Connection timeout (default: {DEFAULT_TIMEOUT})
  -delay <seconds>               Delay between ports (rate limiting)
  -sV                            Enable service detection
  -A                             Aggressive scan (service + latency)
  -v                             Verbose output
  -vv                            Very verbose (show closed ports)
  -o <file>                      Save results to JSON file
  -sU                            UDP scan (experimental)
  -sT                            TCP connect scan (default)

{Colors.CYAN}Monitoring & Analysis:{Colors.RESET}
  monitor <target> -p <port>     Monitor single port for changes
  dns <hostname>                 Perform DNS lookup
  report                         Generate report from last scan
  history                        Show command history

{Colors.CYAN}Utility Commands:{Colors.RESET}
  help                           Show this help message
  clear                          Clear screen
  exit                           Exit application

{Colors.CYAN}Examples:{Colors.RESET}
  scan scanme.nmap.org -p 1-1000 -t 300 -sV
  scan 192.168.1.1 -fast -v
  scan example.com -p 80-443 -A -o results.json
  monitor example.com -p 80 -interval 5

{Colors.YELLOW}Note: This tool is for authorized security testing only.{Colors.RESET}
"""
    
    safe_print(help_text)
    safe_input(f"{Colors.WHITE}Press ENTER to continue...{Colors.RESET}")


def main():
    """Main application loop"""
    
    load_config()
    load_history()
    
    
    print_banner()
    safe_print(f"{Colors.WHITE}Welcome to XLScanner - Professional Port Scanner{Colors.RESET}")
    safe_print(f"{Colors.YELLOW}Type 'help' for command list{Colors.RESET}\n")
    

    while True:
        try:
            prompt = f"{Colors.GREEN}xlscanner{Colors.WHITE}>{Colors.RESET} "
            cmd = safe_input(prompt)
            
            if not cmd:
                continue
            
            cmd_lower = cmd.lower().strip()
            
            
            if cmd_lower.startswith("scan "):
                perform_scan(cmd)
            
            elif cmd_lower.startswith("monitor "):
                cmd_monitor(cmd)
            
            elif cmd_lower.startswith("dns "):
                cmd_dns(cmd)
            
            elif cmd_lower == "history":
                cmd_history()
            
            elif cmd_lower == "report":
                cmd_report()
            
            elif cmd_lower == "help":
                cmd_help()
            
            elif cmd_lower == "clear":
                print_banner()
            
            elif cmd_lower in ("exit", "quit", "q"):
                safe_print(f"\n{Colors.GREEN}Thank you for using XLScanner!{Colors.RESET}")
                safe_print(f"{Colors.CYAN}Stay secure, scan responsibly.{Colors.RESET}\n")
                sys.exit(0)
            
            else:
                safe_print(f"{Colors.YELLOW}Unknown command. Type 'help' for available commands.{Colors.RESET}")
        
        except KeyboardInterrupt:
            safe_print(f"\n{Colors.YELLOW}Use 'exit' to quit{Colors.RESET}")
            continue
        
        except Exception as e:
            safe_print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            if state.config.get("verbose"):
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        safe_print(f"\n\n{Colors.GREEN}Goodbye!{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        safe_print(f"\n{Colors.RED}Fatal error: {e}{Colors.RESET}")

        sys.exit(1)
