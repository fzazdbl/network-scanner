#!/usr/bin/env python3
"""
scanner.py — Scanner réseau Python (pur stdlib, pas de scapy)
Auteur : Mohamed Chahid Echattioui (@fzazdbl)
"""

import argparse
import ipaddress
import platform
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── ANSI ──────────────────────────────────────────────────────────────────────
R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
MAG = "\033[95m"
BLU = "\033[94m"
DIM = "\033[2m"


def c(text, code):
    return f"{code}{text}{R}"


# ── Services connus ────────────────────────────────────────────────────────────
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle-DB", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# Probes par service pour le banner grabbing
PROBES = {
    22:   b"SSH-2.0-Scanner\r\n",
    21:   b"",
    80:   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    25:   b"",
    110:  b"",
    143:  b"",
}


def banner():
    print(f"""
{MAG}{BOLD}
  ███╗   ██╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{R}{CYN}  Scanner réseau Python (stdlib)  |  @fzazdbl{R}
""")


# ── ARP Discovery ─────────────────────────────────────────────────────────────
def arp_discovery(network: ipaddress.IPv4Network) -> list[dict]:
    """Découverte ARP via ping + lecture table ARP système."""
    hosts = list(network.hosts())
    print(c(f"\n  Ping sweep sur {network} ({len(hosts)} hôtes)...\n", YEL))

    alive = []
    system = platform.system().lower()

    def ping_one(ip_str: str) -> bool:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "500", ip_str]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip_str]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(ping_one, str(h)): str(h) for h in hosts}
        for fut in as_completed(futures):
            ip_str = futures[fut]
            if fut.result():
                alive.append(ip_str)

    # Lire la table ARP pour récupérer les MAC
    arp_table = {}
    try:
        if system == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10)

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                for i, part in enumerate(parts):
                    if any(c_ in part for c_ in ["-", ":"]) and len(part) >= 11:
                        # Possible MAC address
                        # L'IP est souvent la partie juste avant ou après
                        for p in parts:
                            try:
                                ipaddress.IPv4Address(p)
                                arp_table[p] = part
                                break
                            except ValueError:
                                continue
    except Exception:
        pass

    results = []
    for ip in sorted(alive, key=lambda x: ipaddress.IPv4Address(x)):
        mac = arp_table.get(ip, "N/A")
        hostname = "N/A"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        results.append({"ip": ip, "mac": mac, "hostname": hostname})

    return results


def print_arp_results(hosts: list[dict]) -> None:
    if not hosts:
        print(c("  Aucun hôte détecté.", YEL))
        return

    print(f"  {c('IP', BLU + BOLD):<30} {c('MAC', BLU + BOLD):<25} {c('HOSTNAME', BLU + BOLD)}")
    print(f"  {'─' * 70}")
    for h in hosts:
        print(
            f"  {c(h['ip'], GRN + BOLD):<22} "
            f"{c(h['mac'], CYN):<25} "
            f"{c(h['hostname'], DIM)}"
        )
    print(c(f"\n  {len(hosts)} hôte(s) actif(s)\n", CYN + BOLD))


# ── Port Scan ─────────────────────────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Tente de récupérer le banner d'un service."""
    probe = PROBES.get(port, b"")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                try:
                    s.sendall(probe)
                except Exception:
                    pass
            try:
                raw = s.recv(512)
                decoded = raw.decode("utf-8", errors="replace").strip()
                first_line = decoded.splitlines()[0][:100] if decoded else ""
                return first_line
            except Exception:
                return ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float = 1.5) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            banner_str = grab_banner(ip, port, timeout)
            return port, True, banner_str
    except (ConnectionRefusedError, OSError, socket.timeout):
        return port, False, ""


def port_scan(target: str, port_range: str, timeout: float = 1.5, workers: int = 200) -> list[tuple]:
    # Parser les ports
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))

    print(c(f"\n  Port scan TCP : {target} — {len(ports)} ports ({port_range})\n", YEL))

    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, target, p, timeout): p for p in ports}
        done = 0
        for fut in as_completed(futures):
            done += 1
            port, is_open, banner_str = fut.result()
            if is_open:
                open_ports.append((port, SERVICES.get(port, "?"), banner_str))
            # Progression
            if done % 200 == 0 or done == len(ports):
                pct = done * 100 // len(ports)
                sys.stdout.write(f"\r  Progression : {pct}% ({done}/{len(ports)})")
                sys.stdout.flush()

    print()
    open_ports.sort()
    return open_ports


def print_scan_results(results: list[tuple], target: str) -> None:
    if not results:
        print(c(f"  Aucun port ouvert sur {target}\n", YEL))
        return

    print(f"\n  {c('PORT', BLU + BOLD):<20} {c('SERVICE', BLU + BOLD):<20} {c('BANNER/INFO', BLU + BOLD)}")
    print(f"  {'─' * 75}")
    for port, svc, banner_str in results:
        banner_display = (banner_str[:55] + "…") if len(banner_str) > 55 else banner_str
        print(
            f"  {c(str(port), GRN + BOLD):<12}"
            f"  {c(svc, CYN):<20}"
            f"  {c(banner_display, DIM)}"
        )
    print(c(f"\n  {len(results)} port(s) ouvert(s) sur {target}\n", CYN + BOLD))


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Scanner réseau Python (stdlib) — ARP discovery + port scan TCP + banner grabbing",
    )
    p.add_argument("--target", "-t", required=True,
                   help="IP, hostname, ou réseau CIDR (ex: 192.168.1.0/24)")
    p.add_argument("--scan", "-s",
                   choices=["arp", "ports", "all"],
                   default="all",
                   help="Type de scan : arp (découverte), ports (TCP), all (les deux, défaut)")
    p.add_argument("--range", "-r", dest="port_range", default="1-1024",
                   help="Plage de ports pour le scan TCP (défaut: 1-1024)")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Timeout de connexion en secondes (défaut: 1.5)")
    p.add_argument("--workers", "-w", type=int, default=200,
                   help="Threads parallèles pour le scan (défaut: 200)")
    p.add_argument("--no-banner", action="store_true")
    return p


def resolve_target(target: str) -> str:
    """Résout un hostname en IP si nécessaire."""
    try:
        ipaddress.IPv4Address(target)
        return target
    except ValueError:
        try:
            ipaddress.IPv4Network(target, strict=False)
            return target
        except ValueError:
            try:
                ip = socket.gethostbyname(target)
                print(c(f"  Résolution : {target} → {ip}", DIM))
                return ip
            except socket.gaierror:
                return target


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        banner()

    target = resolve_target(args.target)
    scan_type = args.scan

    # Détecter si c'est un réseau ou une IP unique
    try:
        net = ipaddress.IPv4Network(target, strict=False)
        is_network = net.prefixlen < 32
    except ValueError:
        is_network = False
        net = None

    if scan_type in ("arp", "all"):
        if is_network and net:
            hosts = arp_discovery(net)
            print_arp_results(hosts)

            if scan_type == "all" and hosts:
                for h in hosts:
                    results = port_scan(h["ip"], args.port_range, args.timeout, args.workers)
                    print_scan_results(results, h["ip"])
        else:
            # IP unique : juste vérifier si up via ping
            print(c(f"\n  Cible unique ({target}) — skip ARP, passage direct au scan ports", YEL))
            if scan_type in ("ports", "all"):
                results = port_scan(target, args.port_range, args.timeout, args.workers)
                print_scan_results(results, target)
    elif scan_type == "ports":
        if is_network and net:
            # Scanner les ports de chaque hôte du réseau
            print(c(f"\n  Scan ports sur réseau {net}", YEL))
            hosts_up = arp_discovery(net)
            print_arp_results(hosts_up)
            for h in hosts_up:
                results = port_scan(h["ip"], args.port_range, args.timeout, args.workers)
                print_scan_results(results, h["ip"])
        else:
            results = port_scan(target, args.port_range, args.timeout, args.workers)
            print_scan_results(results, target)


if __name__ == "__main__":
    main()
