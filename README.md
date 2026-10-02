# LogHunter 🎯

**LogHunter** is an automated PowerShell forensic auditing and anti-cheat inspection tool. It gathers critical system artifacts, analyzes Windows Event Logs, verifies service integrity, and flags potential indicators of compromise (IoCs), log wiping, or user tampering.

## 🚀 Usage

### Option 1: Direct Memory Execution (Recommended)
Open PowerShell as Administrator and execute:

irm "https://raw.githubusercontent.com/tqmgxd/loghunter/main/script.ps1" | iex

---

## 🔍 Key Features & Inspections

* **Boot & Uptime Verification:** Compares WMI boot timestamps against Kernel-General events to detect system clock manipulation or log tampering.
* **Log Wiping Detection:** Scans for critical security events such as manually cleared Event Logs (Event ID 1102 / 104) and system time changes (Event ID 4616).
* **Core Services Audit:** Checks the status and startup configuration of key tracking services (SysMain, PcaSvc, BAM, EventLog, DPS, Schedule).
* **FileSystem & Deletion Tracking:** Analyzes the USN Journal (fsutil) and Recycle Bin for recent file purges and trace wiping attempts.
* **System Policy & Registry Checks:** Inspects PowerShell ScriptBlock Logging, CMD disable policies, and Prefetch status.
* **Process & Execution Monitoring:** Scans Process Creation events (Event ID 4688) and ConsoleHost history (ConsoleHost_history.txt) for suspicious commands or scripts.
* **System Binary Integrity:** Validates digital signatures on critical core binaries (e.g., calc.exe) to flag binary replacement/planting.
* **USB Activity Logs:** Detects recent removable drive insertions and removals.

---

## ⚠️ Requirements

* **OS:** Windows 10 / 11 or Windows Server.
* **Privileges:** Administrator rights are strongly recommended. Running in a non-elevated session limits access to Security logs and USN Journal analysis.

---

## 📄 License

This project is licensed under the MIT License (LICENSE).
