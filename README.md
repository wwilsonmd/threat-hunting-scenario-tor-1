# 🛡️ Threat Hunt Case Study: Unauthorized TOR Usage

![Status](https://img.shields.io/badge/Status-Completed-success)  
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Defender%20XDR-blue)  
![Focus](https://img.shields.io/badge/Focus-Threat%20Hunting-orange)  
![MITRE](https://img.shields.io/badge/MITRE-T1090.003-red)

---

## 📖 Overview
This project documents a real-world **threat hunting investigation** where suspicious encrypted traffic led to the discovery of **unauthorized TOR browser usage** on a corporate endpoint.

---

## 🎯 Scenario
Management suspected employees were bypassing network restrictions using anonymization tools due to:
- Unusual encrypted traffic patterns  
- Connections to known TOR nodes  
- Anonymous internal reports  

---

## 🧠 Skills Demonstrated
- Threat Hunting (Microsoft Defender XDR)
- Kusto Query Language (KQL)
- Incident Investigation & Timeline Analysis
- IOC Development
- MITRE ATT&CK Mapping
- Blue Team Detection Engineering

---

## 🔍 Investigation Summary

| Category | Finding |
|----------|--------|
| Initial Access | TOR installer downloaded |
| Execution | Silent install using `/S` flag |
| Persistence | Portable TOR Browser on Desktop |
| Activity | Multiple TOR processes executed |
| C2 Communication | Connection to TOR relay (port 9001) |

---

## 🧪 KQL Queries Used

### 📁 File Discovery
```kql
DeviceFileEvents
| where DeviceName == "michael-windows"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-05 21:35:48)
| order by Timestamp desc

⚙️ Process Execution Detection
DeviceProcessEvents
| where DeviceName == "michael-windows"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"

🧠 TOR Process Activity
DeviceProcessEvents
| where FileName has_any ("tor.exe", "firefox.exe", "start-tor-browser.exe")
| order by Timestamp desc

🌐 Network Detection
DeviceNetworkEvents
| where RemotePort in ("9001","9030","9050","9150","443")
| where InitiatingProcessFileName == "tor.exe"

🧾 Indicators of Compromise (IOCs)

🔑 File Hashes
958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b
5d7797c72d7eae405d6b2054d94c53494861eb1169d8a1b276775aa48dc94fd7

🌐 Network Indicators
IP Address: 78.31.250.68
Port: 9001
Domain: https://www.y4rfgxj4ds6tlrlho.com

📂 Suspicious Paths
C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe
C:\Users\labuser\Desktop\Tor Browser\

🕒 Attack Timeline
21:35:48  - TOR files appear on system
21:40:21  - Installer executed
21:52:41  - Silent install (/S flag)
21:53:59  - TOR browser launched
21:54:03  - tor.exe starts
21:55:53  - External TOR connection established
22:10:40  - Continued TOR activity

🧠 MITRE ATT&CK Mapping
Technique	ID	Description
Multi-hop Proxy (TOR)	T1090.003	Anonymous communication
Defense Evasion	T1564	Silent installation
Execution	T1059	Process execution
C2 Communication	T1071	Encrypted traffic

⚠️ Risk Analysis
🔒 Bypasses network monitoring controls
📤 Potential data exfiltration channel
🕵️ Indicates intentional evasion behavior
🚫 Violates corporate security policy

🛠️ Response Actions
✅ Endpoint isolated
✅ Activity confirmed
✅ Management notified

🔐 Detection & Prevention Recommendations
Detection Engineering
Alert on:
tor.exe execution
Silent installs (/S)
TOR ports (9001–9152)
Network Controls
Block TOR-related ports:
9001, 9030, 9050–9152
Endpoint Hardening
Application allowlisting
Restrict portable executable execution

🚀 Key Takeaways
TOR usage can be detected through endpoint + network correlation
Silent installs are a strong defense evasion indicator
Combining process + network telemetry is critical for attribution
📎 Source Data

See original investigation notes in this repository.


---
