#!/usr/bin/env python3
"""
Network Scanner — Cybersecurity Project
-----------------------------------------
Features:
  1. Host Discovery          : ARP scan to find live hosts on a local subnet.
  2. Port Scanning            : Multithreaded TCP connect scan.
  3. SYN Scan                 : Half-open TCP scan (stealthier, no full handshake).
  4. UDP Scan                 : UDP probe scan with ICMP-based state classification.
  5. Service Detection        : Expanded port->service map + active banner probing.
  6. OS Detection (basic)     : TTL-based OS fingerprinting via ICMP.
  7. Color Output             : ANSI-colored terminal output.
  8. Progress Bar             : Live progress indicator during scans.
  9. Multi-Host Scan          : Scan several hosts/CIDRs in one run (comma-separated).
 10. Scan Report Export       : Save results to a .txt report on request.

Author : Sharad Jangir
Course : Cybersecurity — Network Scanner Project
Run on : Kali Linux (requires root for ARP scan, SYN scan, UDP scan, and OS detection)

Usage examples:
  sudo python3 network_scanner.py --discover -t 192.168.1.0/24
  python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000
  python3 network_scanner.py --portscan -t 192.168.1.5 -p 22,80,443 --banner
  sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --syn
  sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 53,123,161 --udp
  sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --syn --udp
  sudo python3 network_scanner.py --portscan -t 192.168.1.5,192.168.1.6,10.0.0.0/29 -p 1-1000
  sudo python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --os --save
  python3 network_scanner.py --portscan -t 192.168.1.5 -p 1-1000 --no-color --no-progress
"""

import argparse
import ipaddress
import os
import socket
import sys
import threading
import queue
import time
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, UDP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ------------------------------- Color Output ------------------------------ #

class Colors:
    """ANSI color codes. Disabled globally by set_color_enabled(False)."""
    ENABLED = True

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def wrap(cls, text, code):
        if not cls.ENABLED:
            return text
        return f"{code}{text}{cls.RESET}"


def set_color_enabled(enabled):
    Colors.ENABLED = enabled


def c_green(text):
    return Colors.wrap(text, Colors.GREEN)


def c_red(text):
    return Colors.wrap(text, Colors.RED)


def c_yellow(text):
    return Colors.wrap(text, Colors.YELLOW)


def c_cyan(text):
    return Colors.wrap(text, Colors.CYAN)


def c_bold(text):
    return Colors.wrap(text, Colors.BOLD)


# --------------------------- Input Validation --------------------------- #

def validate_cidr(target_range):
    """Validate a CIDR string (e.g. 192.168.1.0/24). Exit with a clean error if invalid."""
    try:
        ipaddress.ip_network(target_range, strict=False)
    except ValueError:
        print(c_red(f"[-] Invalid target range: '{target_range}'"))
        print("    Expected a CIDR block, e.g. 192.168.1.0/24")
        sys.exit(1)
    return target_range


def validate_host(target):
    """Resolve/validate a single IP or hostname. Exit with a clean error if invalid."""
    if not target or not target.strip():
        print(c_red("[-] Target cannot be empty."))
        sys.exit(1)
    try:
        return socket.gethostbyname(target.strip())
    except socket.gaierror:
        print(c_red(f"[-] Could not resolve target: '{target}'"))
        print("    Check the hostname/IP is correct and reachable.")
        sys.exit(1)


def has_local_route(target_ip):
    """Check local routing without sending a packet to the target."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_ip, 9))
        return True
    except OSError:
        return False


ESSENTIAL_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]


def validate_ports(port_arg):
    """
    Parse and validate a port spec like '1-1000', '22,80,443', or '-'.
    A missing value or 'common' selects the essential-port set. A single '-'
    means all ports, matching Nmap's '-p-' syntax.
    Returns a sorted list of valid ints in [1, 65535]. Exits cleanly on bad input.
    """
    MIN_PORT, MAX_PORT = 1, 65535
    ports = set()

    if port_arg is None or not port_arg.strip() or port_arg.strip().lower() == "common":
        return ESSENTIAL_PORTS.copy()

    if port_arg.strip() == "-":
        return list(range(MIN_PORT, MAX_PORT + 1))

    for raw_part in port_arg.split(","):
        part = raw_part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_s, _, end_s = part.partition("-")
                start, end = int(start_s), int(end_s)
                if start > end:
                    print(c_red(f"[-] Invalid port range '{part}': start is greater than end."))
                    sys.exit(1)
                if start < MIN_PORT or end > MAX_PORT:
                    print(c_red(f"[-] Port range '{part}' out of bounds ({MIN_PORT}-{MAX_PORT})."))
                    sys.exit(1)
                ports.update(range(start, end + 1))
            else:
                p = int(part)
                if p < MIN_PORT or p > MAX_PORT:
                    print(c_red(f"[-] Port {p} out of bounds ({MIN_PORT}-{MAX_PORT})."))
                    sys.exit(1)
                ports.add(p)
        except ValueError:
            print(c_red(f"[-] Invalid port value: '{part}' (must be a number or a range like 20-80)"))
            sys.exit(1)

    if not ports:
        print(c_red("[-] No valid ports parsed from input."))
        sys.exit(1)

    return sorted(ports)


def validate_threads(threads, num_ports):
    """Clamp/validate thread count to something sane."""
    if threads < 1:
        print(c_red(f"[-] --threads must be at least 1 (got {threads})."))
        sys.exit(1)
    if threads > 500:
        print(c_yellow(f"[!] --threads {threads} is very high, clamping to 500 to avoid system strain."))
        threads = 500
    return min(threads, num_ports) or 1


def is_root():
    return os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0


def require_root_for_raw(feature_name):
    """Exit cleanly if raw-socket privileges are missing for a requested feature."""
    if not SCAPY_AVAILABLE:
        print(c_red(f"[-] {feature_name} requires Scapy. Run: pip install scapy --break-system-packages"))
        sys.exit(1)
    if not is_root():
        print(c_red(f"[-] {feature_name} requires root privileges (raw sockets). Try running with sudo."))
        sys.exit(1)


# --------------------------- Multi-Host Targeting --------------------------- #

MAX_AUTO_EXPAND_HOSTS = 256
MAX_HARD_EXPAND_HOSTS = 65536


def expand_targets(target_arg, no_prompt=False):
    """
    Expand a comma-separated target argument into a flat, de-duplicated list
    of individual hosts/IPs. Each comma-separated entry may be:
      - a single IP or hostname                (192.168.1.5, example.com)
      - a CIDR block, expanded to every host    (10.0.0.0/29)
    Exits/prompts if a CIDR would expand to an unreasonably large host count.
    """
    targets = []

    for raw in target_arg.split(","):
        part = raw.strip()
        if not part:
            continue

        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError:
                print(c_red(f"[-] Invalid CIDR '{part}', skipping."))
                continue

            if net.version != 4:
                print(c_red(f"[-] IPv6 target '{part}' is not supported; use an IPv4 range."))
                continue

            if net.version == 4:
                host_count = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
            else:
                host_count = net.num_addresses if net.prefixlen >= 127 else net.num_addresses - 2

            if host_count > MAX_HARD_EXPAND_HOSTS:
                print(c_red(
                    f"[-] Refusing to expand '{part}' to {host_count} hosts; "
                    f"the hard limit is {MAX_HARD_EXPAND_HOSTS}."
                ))
                continue

            if host_count > MAX_AUTO_EXPAND_HOSTS:
                print(c_yellow(
                    f"[!] '{part}' expands to {host_count} hosts, which is a lot for a single scan."
                ))
                if no_prompt:
                    print(c_red(f"[-] Refusing to auto-expand {host_count} hosts with --no-prompt set. "
                                 f"Use a smaller range."))
                    sys.exit(1)
                try:
                    answer = input(c_cyan(f"    Continue and scan all {host_count} hosts? (y/n): ")).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    sys.exit(1)
                if answer not in ("y", "yes"):
                    print(c_yellow(f"[-] Skipping '{part}'."))
                    continue

            hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
            targets.extend(hosts)
        else:
            targets.append(part)

    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)

    if not unique_targets:
        print(c_red("[-] No valid targets parsed from --target."))
        sys.exit(1)

    return unique_targets


# ----------------------------- Progress Bar ----------------------------- #

progress_lock = threading.Lock()
PROGRESS_ENABLED = True


def set_progress_enabled(enabled):
    global PROGRESS_ENABLED
    PROGRESS_ENABLED = enabled


def print_progress(done, total, prefix="Progress", bar_len=30):
    """Thread-safe single-line progress bar. No-op if disabled or total is 0."""
    if not PROGRESS_ENABLED or total <= 0:
        return
    with progress_lock:
        fraction = min(done / total, 1.0)
        filled = int(bar_len * fraction)
        bar = "#" * filled + "-" * (bar_len - filled)
        percent = fraction * 100
        sys.stdout.write(f"\r{prefix}: |{bar}| {percent:5.1f}% ({done}/{total})")
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()


# ----------------------------- Host Discovery ----------------------------- #

def arp_scan(target_ip_range):
    """
    Send ARP requests to every IP in the given range/CIDR and report
    which hosts respond (i.e., are alive on the LAN).
    """
    if not SCAPY_AVAILABLE:
        print(c_red("[-] Scapy is not installed. Run: pip install scapy --break-system-packages"))
        sys.exit(1)

    if not is_root():
        print(c_red("[-] ARP scanning requires root privileges. Try: sudo python3 network_scanner.py --discover -t <range>"))
        sys.exit(1)

    validate_cidr(target_ip_range)
    if ipaddress.ip_network(target_ip_range, strict=False).version != 4:
        print(c_red("[-] ARP discovery supports IPv4 CIDR ranges only."))
        sys.exit(1)

    print(f"[*] Starting ARP scan on {target_ip_range} ...\n")

    arp_request = ARP(pdst=target_ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, retry=0, verbose=False)

    live_hosts = []
    for sent, received in answered:
        live_hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    if live_hosts:
        print(c_bold(f"{'IP Address':<18}{'MAC Address'}"))
        print("-" * 40)
        for host in live_hosts:
            print(f"{c_green(host['ip']):<27}{host['mac']}")
        print(c_green(f"\n[+] {len(live_hosts)} live host(s) found."))
    else:
        print(c_yellow("[-] No live hosts found. Try running with sudo, or check the target range."))

    return live_hosts


# ----------------------------- OS Detection ----------------------------- #

def os_detect(target_ip):
    """
    Very basic OS fingerprinting using the TTL of an ICMP echo reply.
    This is a heuristic, not a definitive identification (real OS detection,
    like nmap's -O, uses many more signals: TCP window size, options order, etc.)

    Common default TTLs:
      Linux/Unix/macOS  -> 64
      Windows           -> 128
      Cisco/Solaris/etc -> 255
    """
    if not SCAPY_AVAILABLE:
        return "Unknown (scapy not installed)"

    if not is_root():
        return "Unknown (requires root for raw ICMP packets)"

    try:
        pkt = IP(dst=target_ip) / ICMP()
        reply = sr1(pkt, timeout=2, retry=0, verbose=False)
        if reply is None:
            return "Unknown (no ICMP reply — host may block ping)"

        ttl = reply.ttl
        if ttl <= 64:
            guess = "Linux / Unix / macOS"
        elif ttl <= 128:
            guess = "Windows"
        else:
            guess = "Network device (Cisco/Solaris) or unusual TTL"
        return f"{guess}  (TTL={ttl})"
    except PermissionError:
        return "Unknown (permission denied — run with sudo)"
    except Exception as e:
        return f"Unknown (error: {e})"


# ------------------------------ Service Detection ------------------------------ #

# Expanded common-ports map for cleaner "SERVICE" column output.
COMMON_PORTS_BANNER_HINT = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBIND", 123: "NTP", 135: "MSRPC", 137: "NETBIOS-NS",
    138: "NETBIOS-DGM", 139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-TRAP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 587: "SMTP-SUBMISSION", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "ORACLE",
    2049: "NFS", 27017: "MONGODB", 3306: "MYSQL", 3389: "RDP",
    5432: "POSTGRESQL", 5900: "VNC", 5985: "WINRM", 6379: "REDIS",
    8000: "HTTP-ALT", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 9200: "ELASTICSEARCH",
}

# Ports where sending a small protocol probe gets a far more useful banner
# than just calling recv() and hoping the service talks first.
HTTP_LIKE_PORTS = {80, 8000, 8080, 8443, 443}

print_lock = threading.Lock()
SCAN_STOP_EVENT = threading.Event()


def grab_banner(sock, port, target):
    """
    Try to read a service banner from an already-connected socket.
    For HTTP-like ports, send a minimal HEAD request first since most
    web servers wait for the client to speak before responding.
    """
    try:
        sock.settimeout(1.5)
        if port in HTTP_LIKE_PORTS:
            probe = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
            sock.sendall(probe)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        # Collapse to first meaningful line (e.g. "HTTP/1.1 200 OK" or SSH version string)
        first_line = banner.splitlines()[0] if banner else ""
        return first_line if first_line else None
    except Exception:
        return None


class ScanCounter:
    """Simple thread-safe completion counter, used to drive the progress bar."""

    def __init__(self, total):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()

    def tick(self, prefix):
        with self.lock:
            self.done += 1
            done = self.done
        print_progress(done, self.total, prefix=prefix)


# ------------------------- TCP Connect Scan ------------------------- #

def scan_port_connect(target, port, show_banner, open_ports, counter, prefix):
    """Attempt a TCP connect to a single port. Stores (port, service, state, banner) on success."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS_BANNER_HINT.get(port, "unknown")
                banner = grab_banner(sock, port, target) if show_banner else None
                with print_lock:
                    open_ports.append((port, service, "OPEN", banner))
    except Exception:
        pass
    finally:
        counter.tick(prefix)


def connect_worker(target, show_banner, open_ports, port_queue, counter, prefix):
    while not SCAN_STOP_EVENT.is_set():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        try:
            scan_port_connect(target, port, show_banner, open_ports, counter, prefix)
        finally:
            port_queue.task_done()


def run_connect_scan(target, ports, threads, show_banner):
    open_ports = []
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    counter = ScanCounter(len(ports))
    prefix = f"TCP connect scan {target}"

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=connect_worker,
                              args=(target, show_banner, open_ports, port_queue, counter, prefix))
        t.daemon = True
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

    open_ports.sort(key=lambda x: x[0])
    return open_ports


# ------------------------------ SYN Scan ------------------------------ #
# Half-open scan: we send a SYN and inspect the reply, but never complete
# the handshake, so no banner grabbing is possible here (that needs a full
# connection). Faster and stealthier than a connect scan, at the cost of
# needing raw sockets (root).

def scan_port_syn(target, port, results, counter, prefix):
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, retry=0, verbose=False)
        service = COMMON_PORTS_BANNER_HINT.get(port, "unknown")

        if resp is None:
            pass  # no reply: likely filtered by a firewall, don't report as open
        elif resp.haslayer(TCP):
            flags = int(resp.getlayer(TCP).flags)
            if flags & 0x12 == 0x12:  # SYN+ACK -> open
                # tear down the half-open connection cleanly
                rst = IP(dst=target) / TCP(
                    sport=resp[TCP].dport,
                    dport=resp[TCP].sport,
                    flags="R",
                    seq=resp[TCP].ack,
                )
                send(rst, count=1, verbose=False)
                with print_lock:
                    results.append((port, service, "OPEN", None))
            elif flags & 0x14 == 0x14:  # RST+ACK -> closed, don't report
                pass
        elif resp.haslayer(ICMP):
            icmp_layer = resp.getlayer(ICMP)
            if int(icmp_layer.type) == 3:  # destination unreachable -> filtered
                with print_lock:
                    results.append((port, service, "FILTERED", None))
    except Exception:
        pass
    finally:
        counter.tick(prefix)


def syn_worker(target, results, port_queue, counter, prefix):
    while not SCAN_STOP_EVENT.is_set():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        try:
            scan_port_syn(target, port, results, counter, prefix)
        finally:
            port_queue.task_done()


def run_syn_scan(target, ports, threads):
    require_root_for_raw("SYN scanning")
    results = []
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    counter = ScanCounter(len(ports))
    prefix = f"SYN scan {target}"

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=syn_worker, args=(target, results, port_queue, counter, prefix))
        t.daemon = True
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

    results.sort(key=lambda x: x[0])
    return results


# ------------------------------ UDP Scan ------------------------------ #
# UDP is connectionless and stateless, so results are inherently ambiguous:
#   - A UDP reply from the service         -> OPEN
#   - ICMP type 3 / code 3 (port unreach.) -> CLOSED (not reported)
#   - Any other ICMP unreachable           -> FILTERED
#   - No response at all (very common      -> OPEN|FILTERED
#     since most services stay silent on
#     unexpected input)

def scan_port_udp(target, port, results, counter, prefix):
    try:
        pkt = IP(dst=target) / UDP(dport=port)
        resp = sr1(pkt, timeout=1.5, retry=0, verbose=False)
        service = COMMON_PORTS_BANNER_HINT.get(port, "unknown")

        if resp is None:
            with print_lock:
                results.append((port, service, "OPEN|FILTERED", None))
        elif resp.haslayer(ICMP) and resp.haslayer(IP) and resp[IP].src == target:
            icmp_layer = resp.getlayer(ICMP)
            if int(icmp_layer.type) == 3 and int(icmp_layer.code) == 3:
                pass  # port unreachable -> closed, don't report
            else:
                with print_lock:
                    results.append((port, service, "FILTERED", None))
        elif (resp.haslayer(UDP) and resp.haslayer(IP)
              and resp[IP].src == target and int(resp[UDP].sport) == port):
            with print_lock:
                results.append((port, service, "OPEN", None))
    except Exception:
        pass
    finally:
        counter.tick(prefix)


def udp_worker(target, results, port_queue, counter, prefix):
    while not SCAN_STOP_EVENT.is_set():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        try:
            scan_port_udp(target, port, results, counter, prefix)
        finally:
            port_queue.task_done()


def run_udp_scan(target, ports, threads):
    require_root_for_raw("UDP scanning")
    results = []
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    counter = ScanCounter(len(ports))
    prefix = f"UDP scan {target}"

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=udp_worker, args=(target, results, port_queue, counter, prefix))
        t.daemon = True
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

    results.sort(key=lambda x: x[0])
    return results


def print_banner():
    print(c_cyan("================================="))
    print(c_cyan(c_bold("      Network Scanner v2.0")))
    print(c_cyan("      By Sharad Jangir"))
    print(c_cyan("=================================\n"))


def state_color(state):
    if state == "OPEN":
        return c_green(state)
    if state == "OPEN|FILTERED":
        return c_yellow(state)
    if state == "FILTERED":
        return c_yellow(state)
    return state


def print_results_table(title, results, show_banner=False):
    if not results:
        print(c_yellow(f"\n[{title}] No open/filtered ports found."))
        return

    print(c_bold(f"\n[{title}]"))
    print(c_bold(f"{'PORT':<8}{'STATE':<16}{'SERVICE'}"))
    for port, service, state, banner in results:
        colored_state = state_color(state)
        pad = " " * max(0, 16 - len(state))
        print(f"{port:<8}{colored_state}{pad}{service.upper()}")
        if show_banner and banner:
            print(f"         -> {banner[:70]}")


# ------------------------------ Report Export ------------------------------ #

def build_section_report_lines(title, results):
    lines = [f"[{title}]", f"{'PORT':<8}{'STATE':<16}{'SERVICE'}", "-" * 34]
    for port, service, state, banner in results:
        lines.append(f"{port:<8}{state:<16}{service.upper()}")
        if banner:
            lines.append(f"         -> {banner}")
    lines.append(f"Total: {len(results)}")
    lines.append("")
    return lines


def build_report_text(target_display, target_ip, elapsed, os_guess=None,
                       connect_results=None, syn_results=None, udp_results=None):
    """Build the plain-text scan report content for a single host."""
    lines = []
    lines.append("=================================")
    lines.append("     Network Scanner Report")
    lines.append("=================================")
    lines.append(f"Scan Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Target    : {target_display} ({target_ip})")
    if os_guess:
        lines.append(f"OS Guess  : {os_guess}")
    lines.append("")

    if connect_results is not None:
        lines.extend(build_section_report_lines("TCP CONNECT SCAN", connect_results))
    if syn_results is not None:
        lines.extend(build_section_report_lines("SYN SCAN", syn_results))
    if udp_results is not None:
        lines.extend(build_section_report_lines("UDP SCAN", udp_results))

    lines.append(f"Time Taken : {elapsed:.2f} sec")
    return "\n".join(lines)


def save_report(report_text, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_text + "\n")
        print(c_green(f"[+] Report saved to: {filename}"))
    except (OSError, UnicodeError) as e:
        print(c_red(f"[-] Failed to save report: {e}"))


def default_report_filename(target_display):
    safe_target = target_display.replace("/", "_").replace(":", "_").replace(",", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_report_{safe_target}_{stamp}.txt"


def maybe_save_report(report_text, target_display, auto_save, output_path, no_prompt):
    """
    Decide whether to save the report:
      --save            -> save automatically (uses --output if given, else default name)
      otherwise         -> do not save
    """
    if not auto_save:
        return

    filename = output_path or default_report_filename(target_display)
    save_report(report_text, filename)


# ------------------------------ Port Scanning ------------------------------ #

def scan_single_host(target, ports, threads, do_tcp, do_syn, do_udp,
                      show_banner, detect_os):
    """Run the requested scan type(s) against a single resolved host. Returns report data."""
    target_ip = validate_host(target)
    print(c_bold(f"\n===== Target: {target} ({target_ip}) ====="))

    if not has_local_route(target_ip):
        raise RuntimeError(
            f"Network is unreachable for {target_ip}; check the target, VPN, "
            "network adapter, and routing table."
        )

    os_guess = None
    if detect_os:
        print("[*] Running OS detection ...")
        os_guess = os_detect(target_ip)
        print(f"[*] OS Guess: {c_yellow(os_guess)}\n")

    start_time = time.time()

    connect_results = None
    syn_results = None
    udp_results = None

    if do_tcp:
        connect_results = run_connect_scan(target_ip, ports, threads, show_banner)
        print_results_table("TCP CONNECT SCAN RESULTS", connect_results, show_banner)

    if do_syn:
        syn_results = run_syn_scan(target_ip, ports, threads)
        print_results_table("SYN SCAN RESULTS", syn_results)

    if do_udp:
        udp_results = run_udp_scan(target_ip, ports, threads)
        print_results_table("UDP SCAN RESULTS", udp_results)

    elapsed = time.time() - start_time
    print(f"\nScan Time ({target}): {elapsed:.1f} sec")

    report_text = build_report_text(
        target, target_ip, elapsed, os_guess,
        connect_results=connect_results, syn_results=syn_results, udp_results=udp_results
    )
    return report_text


def port_scan(target_arg, port_arg, threads=100, show_banner=False,
              detect_os=False, do_syn=False, do_udp=False, do_tcp_forced=False,
              auto_save=False, output_path=None, no_prompt=False):
    """
    Entry point for port scanning. Supports multiple comma-separated hosts/CIDRs
    and any combination of TCP connect / SYN / UDP scan types.
    """
    print_banner()
    SCAN_STOP_EVENT.clear()

    targets = expand_targets(target_arg, no_prompt=no_prompt)
    ports = validate_ports(port_arg)
    threads = validate_threads(threads, len(ports))

    # Default to a TCP connect scan unless SYN/UDP were explicitly requested
    # (in which case --tcp can be added to also run a connect scan alongside them).
    do_tcp = do_tcp_forced or not (do_syn or do_udp)

    if len(targets) > 1:
        print(f"[*] Multi-host scan: {len(targets)} target(s) queued.\n")

    all_reports = []
    for idx, target in enumerate(targets, start=1):
        if SCAN_STOP_EVENT.is_set():
            break
        if len(targets) > 1:
            print(c_cyan(f"[Host {idx}/{len(targets)}]"))
        try:
            report = scan_single_host(target, ports, threads, do_tcp, do_syn, do_udp,
                                       show_banner, detect_os)
            all_reports.append(report)
        except SystemExit:
            raise
        except Exception as e:
            print(c_red(f"[-] Error scanning {target}: {e}"))

    combined_report = "\n\n".join(all_reports)
    target_display = target_arg if len(targets) == 1 else f"{len(targets)}_hosts"
    maybe_save_report(combined_report, target_display, auto_save, output_path, no_prompt)


# ---------------------------------- Main ---------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Simple Network Scanner (ARP host discovery + TCP/SYN/UDP port scan)",
        epilog=(
            "Port examples:\n"
            "  -p                 Scan essential/common ports\n"
            "  -p 80              Scan one port\n"
            "  -p 22,80,443       Scan selected ports\n"
            "  -p 1-1000          Scan a port range\n"
            "  -p-                Scan all ports (1-65535)\n\n"
            "Example:\n"
            "  python network_scanner.py --portscan -t 192.168.1.5 -p-"
        ),
    )
    parser.add_argument("-t", "--target", required=True,
                         help="Target IP, hostname, or CIDR range. Comma-separate multiple "
                              "targets, e.g. '192.168.1.5,192.168.1.10,10.0.0.0/29'")
    parser.add_argument("--discover", action="store_true",
                         help="Run ARP host discovery on the target subnet (requires root)")
    parser.add_argument("--portscan", action="store_true",
                         help="Run a port scan on the target host(s)")
    parser.add_argument("-p", "--ports", nargs="?", const="common", default="common",
                            help="Port selection: -p for essential ports, a number/list/range for "
                                "custom ports, or -p- for all ports")
    parser.add_argument("--threads", type=int, default=100,
                         help="Number of threads for port scanning (default: 100)")
    parser.add_argument("--banner", action="store_true",
                         help="Attempt banner grabbing on open ports (TCP connect scan only)")
    parser.add_argument("--os", action="store_true", dest="detect_os",
                         help="Attempt basic OS detection via ICMP TTL (requires root)")
    parser.add_argument("--tcp", action="store_true",
                         help="Force a TCP connect scan even when --syn/--udp are also set "
                              "(a plain connect scan runs by default when neither is set)")
    parser.add_argument("--syn", action="store_true", dest="do_syn",
                         help="Run a SYN (half-open) scan instead of/alongside a connect scan (requires root)")
    parser.add_argument("--udp", action="store_true", dest="do_udp",
                         help="Run a UDP scan (requires root)")
    parser.add_argument("--save", action="store_true",
                         help="Save the scan report; without this flag, no report is written")
    parser.add_argument("-o", "--output", default=None,
                         help="Filename to use with --save (otherwise no report is written)")
    parser.add_argument("--no-prompt", action="store_true",
                         help="Do not confirm large CIDR expansions")
    parser.add_argument("--no-color", action="store_true",
                         help="Disable colored terminal output")
    parser.add_argument("--no-progress", action="store_true",
                         help="Disable the live progress bar during scans")

    args = parser.parse_args()

    set_color_enabled(not args.no_color)
    set_progress_enabled(not args.no_progress)

    if not args.discover and not args.portscan:
        parser.error("Choose at least one mode: --discover and/or --portscan")

    if not args.target or not args.target.strip():
        parser.error("--target cannot be empty")

    if args.discover:
        for cidr_or_host in [t.strip() for t in args.target.split(",") if t.strip()]:
            try:
                ipaddress.ip_network(cidr_or_host, strict=False)
                discovery_target = cidr_or_host
            except ValueError:
                discovery_target = f"{validate_host(cidr_or_host)}/32"
            arp_scan(discovery_target)
            print()

    if args.portscan:
        port_scan(
            args.target, args.ports,
            threads=args.threads,
            show_banner=args.banner,
            detect_os=args.detect_os,
            do_syn=args.do_syn,
            do_udp=args.do_udp,
            do_tcp_forced=args.tcp,
            auto_save=args.save,
            output_path=args.output,
            no_prompt=args.no_prompt,
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        SCAN_STOP_EVENT.set()
        print("\n[!] Scan stopped by user.")
        sys.exit(130)
