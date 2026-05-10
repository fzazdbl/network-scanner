# network-scanner

> Scanner réseau Python — ARP discovery, port scan TCP, banner grabbing — pur stdlib, sans scapy

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Fonctionnalités

- **ARP Discovery** : ping sweep multithreadé + lecture table ARP système (récupère MAC et hostname)
- **Port scan TCP Connect** : scan parallèle avec 200 workers (ThreadPoolExecutor)
- **Banner Grabbing** : détection automatique des services par lecture du banner réseau
- **30+ services identifiés** : SSH, HTTP/S, FTP, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB…
- **Support CIDR** : scan d'un réseau complet ou d'une IP unique
- Couleurs ANSI, zéro dépendance externe (`socket`, `subprocess`, `concurrent.futures`)

## Installation

```bash
git clone https://github.com/fzazdbl/network-scanner.git
cd network-scanner
python scanner.py --help
```

## Utilisation

```bash
# Scan complet d'un réseau (ARP discovery + port scan)
python scanner.py --target 192.168.1.0/24

# ARP discovery uniquement
python scanner.py --target 192.168.1.0/24 --scan arp

# Port scan d'une IP unique (ports 1-1024)
python scanner.py --target 192.168.1.1 --scan ports

# Port scan sur ports spécifiques
python scanner.py --target 10.0.0.1 --scan ports --range 22,80,443,3389,8080,3306

# Scan full ports (1-65535)
python scanner.py --target 192.168.1.1 --scan ports --range 1-65535

# Timeout et workers personnalisés
python scanner.py --target 192.168.1.0/24 --timeout 0.5 --workers 300
```

## Exemple de sortie

```
  IP                     MAC                       HOSTNAME
  ──────────────────────────────────────────────────────────────────────
  192.168.1.1            a4-c3-f0-xx-xx-xx         router.local
  192.168.1.10           b8-27-eb-xx-xx-xx         raspberrypi
  192.168.1.42           N/A                       desktop-win

  3 hôte(s) actif(s)

  Port scan TCP : 192.168.1.1 — 1024 ports

  PORT        SERVICE              BANNER/INFO
  ───────────────────────────────────────────────────────────────────────
  22          SSH                  SSH-2.0-OpenSSH_8.9p1 Ubuntu
  80          HTTP                 HTTP/1.1 200 OK
  443         HTTPS
  8080        HTTP-Alt             HTTP/1.1 301 Moved Permanently

  4 port(s) ouvert(s)
```

## Options

| Option | Alias | Défaut | Description |
|--------|-------|--------|-------------|
| `--target` | `-t` | — | IP, hostname ou CIDR (requis) |
| `--scan` | `-s` | `all` | `arp` / `ports` / `all` |
| `--range` | `-r` | `1-1024` | Plage de ports (ex: `22,80` ou `1-65535`) |
| `--timeout` | — | `1.5` | Timeout TCP en secondes |
| `--workers` | `-w` | `200` | Threads parallèles pour le scan |
| `--no-banner` | — | — | Désactiver la bannière ASCII |

## Disclaimer

Cet outil est destiné à l'audit de **vos propres réseaux** ou dans le cadre de tests explicitement autorisés. L'utilisation sur des systèmes tiers sans autorisation est illégale.

## Auteur

**Mohamed Chahid Echattioui** — [@fzazdbl](https://github.com/fzazdbl)

## Licence

MIT
