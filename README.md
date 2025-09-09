# 🛡️ PowerShell Threat Feed Scanner

A lightweight PowerShell script that scans your system’s **active TCP connections** and compares them to **real-time malicious IPs** from [URLhaus](https://urlhaus.abuse.ch/).

Built for blue teamers, SOC analysts, and cybersecurity students looking to practice threat hunting using native Windows tools.

---

## Features

- Fetches live threat intelligence IPs from abuse.ch (URLhaus)
- Lists active outbound TCP connections (`Get-NetTCPConnection`)
- Detects and flags matches with known malicious IPs
- Saves suspicious matches to a report file on the desktop
- 100% PowerShell, no external dependencies

---

## How to Test It

First, **open a PowerShell terminal with administrator privileges**.

Then use it to simulate a match with a known malicious IP from the URLhaus feed by running the following **PowerShell one-liner**:

```powershell
$r = New-Object Net.Sockets.TcpClient; $r.Connect("200.59.83.63", 50623); Start-Sleep 10; $r.Close()
```

**This command will give you 10 seconds to simulate a connection** to a malicious IP and port of your choice (e.g. one you found in the URLhaus feed), long enough for the script to detect it in a scan. The connection is then **safely closed automatically**.

While the connection is still active, **open a second PowerShell terminal (also as administrator)** and run your script:

```powershell
.\ThreatFeedScanner.ps1
```

⚠️ **Do not download or interact with content** from these IPs. This test only opens a temporary TCP connection (using `TcpClient`) for detection by the script, no data is transmitted or received.

---

## Usage

```powershell
git clone https://github.com/Athanasios-Oikonomopoulos/PowerShell-Threat-Feed-Scanner.git
cd PowerShell-Threat-Feed-Scanner
.\ThreatFeedScanner.ps1
```

- The script will fetch the feed, scan your active connections, and log any hits.
- You’ll find the log file here:
  ```
  C:\Users\<YourName>\Desktop\ThreatIntelMatches.txt
  ```

---

## 📁 File Structure

```
PowerShell-Threat-Feed-Scanner/
├── ThreatFeedScanner.ps1         # Main script
├── README.md                     # This documentation
├── LICENSE                       # MIT License
└── screenshots/                  # Demo images for README
    ├── Clean_Example.png
    ├── Match_Example.png
    ├── Test_Connection.png
    └── Threat_Intel_Matches.png
```

---

## 📸 Screenshots

### ✅ Clean Result

> Example of no matches (no suspicious IPs detected).

![Clean Example](screenshots/Clean_Example.png)

---

### 🔄 Testing a Malicious Connection

>Opening a raw TCP connection to a known bad IP for detection testing.

![Test Connection](screenshots/Test_Connection.png)

---

### ❌ Malicious Connection Found

> A match was found against a known bad IP from the threat feed.

![Match Example](screenshots/Match_Example.png)

---

### 📝 Threat Intel Log File

> Suspicious IPs are written to a timestamped report on the Desktop.

![Threat Intel Matches](screenshots/Threat_Intel_Matches.png)

---

## 📄 License

This project is licensed under the **MIT License**, open-source and free to use, modify, and share.

---

## ✨ Author

**Athanasios Oikonomopoulos**  
🔗 [LinkedIn](https://www.linkedin.com/in/athanasios-oikonomopoulos/)  
🔗 [TryHackMe](https://tryhackme.com/p/B4ckD00rR4t)  

---

## 🤝 Contribute

Pull requests are welcome! If you want to improve the script, add additional feeds, or customize detection logic, feel free to open an issue or PR.

---

