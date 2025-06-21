# CYBERSECURITY

# 🛡️ Cybersecurity & Ethical Hacking Labs – 2025

This repository documents a series of practical cybersecurity and ethical hacking labs conducted using **Kali Linux**, **VirtualBox**, **Python**, **Wireshark**, **iptables**, **SET Toolkit**, **Snort**, **Cuckoo Sandbox**, and **Shodan**.

---

## 📚 Lab Summary

| Lab No. | Title                                                                 | Tools & Skills Covered                           |
|--------:|------------------------------------------------------------------------|--------------------------------------------------|
| 1       | VirtualBox Setup: Kali Linux & Windows XP                             | VirtualBox, OS setup                             |
| 2       | Website Cloning with SET Toolkit                                       | SET Toolkit, Social Engineering                  |
| 4       | Intrusion Detection using Wireshark & Snort                            | HTTP/FTP packet capture, Snort basics            |
| 5       | Simulating APT & Meterpreter Attack                                    | SET Toolkit, Apache, Meterpreter                 |
| 6       | DDoS Attack with LOIC/Slowloris                                        | Wireshark, Slowloris, Apache                     |
| 7       | Python Keylogger with Ethical Analysis                                 | Python, Pynput, Logging, Ethics                  |
| 8       | Malware Analysis using Cuckoo Sandbox & Wireshark                     | PCAP decryption, VirusTotal, TLS inspection      |
| 9       | IoT Vulnerability Scan using Shodan API                                | Shodan, Python scripting, CSV output             |
| 10      | Firewall Configuration with iptables                                   | iptables, Port filtering, Rate-limiting, DoS defense |

---

## 🔧 Setup Instructions

### ✅ VirtualBox + OS Installation (Lab 1)
- Install **Oracle VirtualBox**.
- Install **Kali Linux** and **Windows XP**.
- Configure RAM, disk space, ISO mounting, and Guest Additions.

---

## 🔓 Social Engineering & Attacks

### 📌 Lab 2: Website Cloning with SET
- Tool: `setoolkit`
- Technique: Credential Harvester → Site Cloner
- Data captured on fake login pages and forwarded to terminal.

### 📌 Lab 5: APT Simulation with Meterpreter
- Create malicious payloads using **SET**.
- Reverse connection via `reverse_tcp`.
- Extract victim data: `hashdump`, `screenshot`, `sysinfo`.

---

## 📈 Traffic Analysis & Forensics

### 📌 Lab 4: IDS with Snort/Wireshark
- Analyze `http` and `ftp` credentials via packet capture.
- Monitor uploads, passwords, and stream decryption.
- Visualize with I/O graphs and protocol filters.

### 📌 Lab 8: Malware Analysis with Wireshark
- Decrypt SSL traffic using session keys.
- Analyze `.dll` payloads.
- Use **VirusTotal** to classify malware (e.g., Dridex).
- Identify infected systems using `nbns` and TLS stream inspection.

---

## 💣 Network Attacks

### 📌 Lab 6: DDoS Simulation (LOIC/Slowloris)
- Use `slowloris.py` to flood victim server on port 80.
- Measure impact using **Wireshark** and Apache logs.

---

## 🛡️ Defense & Mitigation

### 📌 Lab 10: Configuring iptables
- Flush rules and define new policies.
- Block ICMP, limit SSH and HTTP.
- Simulate DoS attacks and mitigate via rate-limiting.
- Create custom logging chains (`LOGGING`).
- Restrict outgoing SSH to specific IPs.

---

## ⌨️ Python Automation

### 📌 Lab 7: Keylogger with Python
- Built using `pynput`
- Records keystrokes to `key_log.txt`
- Extract credentials with regex patterns
- Includes ethical guidelines and countermeasures

### 📌 Lab 9: IoT Scan with Shodan API
- Automated scanning for IoT devices
- Collects open ports, known vulnerabilities
- CSV export and recommendation engine
