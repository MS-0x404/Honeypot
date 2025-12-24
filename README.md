# 🍯 Python Low-Interaction Honeypot

Lightweight low-interaction honeypot that emulates Telnet and FTP services to capture connection attempts and analyze attacker behavior. Built as an academic cyber security project.

## 🚀 Features
- **Dual service emulation:** Telnet (internal port 2323) and FTP (internal port 2121) daemons.
- **Smart threat intelligence:** Integrated with vpnapi.io to detect VPN, Tor nodes, and proxies.
- **Behavioral profiling:** Distinguishes bots vs humans via keystroke latency (typing speed analysis).
- **Secure architecture:** Runs as a non-root user inside the container.
- **Logging:** Detailed logs with timestamps, source IP, commands attempted, and threat-intel data.

## 📦 Quick Start

Prerequisites:
- Python 3.13+
- pip install requests


1) Creare un file .env con la chiave:
```
API_TOKEN=your_apikey
```

2) Eseguire lo script:
```bash
python3 main.py 0.0.0.0 2323
```

## 🐳 Start With Docker

Prerequisites:
- Docker 29+
- (Optional) Docker Compose

1) Eseguire il container (mappa la porta Telnet 23 esterna alla porta 2323 interna):
```bash
docker run -d \
  -p 23:2323 \
  -e API_TOKEN="your_apikey" \
  --name honeypot \
  msfire/honeypot:latest
```

2) Opzioni comuni:
- Mappare anche FTP (porta 21 esterna -> 2121 interna):
```bash
docker run -d \
  -p 23:2323 -p 21:2121 \
  -e API_TOKEN="your_apikey" \
  --name honeypot \
  msfire/honeypot:latest
```

## 🗂 Log e Output
- I log vengono salvati in "/var/log/honeypot/".
- Per esportare i log su host:
```bash
docker run -d \
  -p 23:2323 -p 21:2121 \
  -v $(pwd)/logs:/var/log/honeypot \
  --name honeypot \
  msfire/honeypot:latest
```

## 🛡 Sicurezza e avvertenze
- Il container è progettato per girare come non-root.
- Non esporre servizi su reti di produzione senza adeguati controlli legali e di sicurezza.


## 📜 Licenza
Questo progetto è rilasciato sotto la MIT License — vedi LICENSE per dettagli.
