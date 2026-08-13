# 🛡️ SOC Investigation Report: Phishing Unfolding & DNS Exfiltration

## 📝 Executive Summary
This repository documents the end-to-end investigation of a simulated cyber incident (TryHackMe), in which I acted as a SOC Analyst. The attack began with a sophisticated phishing campaign (*Spray and Pray*), rapidly escalating to endpoint compromise, lateral movement, defense evasion, and exfiltration of critical financial data via DNS.

The objective of this case study is to demonstrate practical skills in threat detection, correlation of network and endpoint logs (Sysmon/EventLogs) using **Splunk**, false positive triage, and TTP mapping using the **MITRE ATT&CK** framework.

---

## 🛠️ Tools & Technologies Used
*   **SIEM:** Splunk (Search Processing Language - SPL)
*   **Endpoint Telemetry:** Sysmon (Process Creation, File Creation)
*   **Email Security:** Email header and payload analysis
*   **Frameworks:** MITRE ATT&CK, Cyber Kill Chain

---

## 🔍 Investigation Timeline (Cyber Kill Chain)

### 1. Delivery & Social Engineering (Phishing Campaign)
The incident began with a massive inbound email campaign. The threat actor continuously rotated its sending infrastructure to evade reputation-based blocks, evolving from text lures to malware delivery.

*   **Techniques Observed:**
    *   Use of anomalous TLDs (`.xyz`, `.online`, `.me`).
    *   Abuse of legitimate webmail (`gmail.com`) for *Defense Evasion*.
    *   Social engineering focused on the target organization's theme.
*   **The Escalation:** The campaign culminated in sending the malicious attachment `ImportantInvoice-Febrary.zip` to the user `michael.ascot`.

### 2. Execution & Initial Access
Endpoint telemetry (`win-3450`) confirmed user interaction with the payload.
*   The `.zip` file was extracted and executed from the directory `C:\Users\michael.ascot\downloads\`.
*   A malicious, persistent instance of `powershell.exe` (PID 3728) was started in the background.

### 3. Discovery & Reconnaissance
The attacker used *Living off the Land* (LotL) tactics and open-source scripts to map the corporate environment.
*   Creation of the file `PowerView.ps1` was identified in the *Downloads* folder.
*   **Objective:** Enumeration of Active Directory (AD) accounts and network shares to identify the financial file server (`FILESRV-01`).

### 4. Lateral Movement & Collection (Staging)
With the target identified, the attacker moved quickly to access the data.
*   **Mapping:** The malicious PowerShell invoked `net.exe` to mount the sensitive network drive: `net use Z: \\FILESRV-01\SSF-FinancialRecords`.
*   **Rapid Collection:** Using the native binary `Robocopy.exe`, the entire contents of the `Z:\` drive were mirrored to a local staging directory created by the attacker: `\downloads\exfiltration\`.

### 5. Defense Evasion & Cleanup
Just 58 seconds after mapping the network drive, the malware executed the removal of the mapping (`net use Z: /delete`). This automation was aimed at hiding traces of the lateral movement to hinder live forensic analysis and avoid arousing user suspicion.

### 6. Exfiltration (C2)
The final and most critical phase of the attack. The attacker packaged the financial data and initiated the theft of the information, bypassing the perimeter firewall.
*   **Technique:** DNS Exfiltration.
*   **Action:** `powershell.exe` triggered multiple queries via `nslookup.exe` to the attacker-controlled domain (`haz4rdw4re.io`). The stolen data was encoded (apparently in Base64) and inserted as subdomains in the requests (e.g., `UEsDBBQAAAAIANigLlfVU3cDlgAAAI.haz4rdw4re.io`).

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence / Observation |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | File `ImportantInvoice-Febrary.zip`. |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution of process PID 3728. |
| **Discovery** | T1087.002 | Account Discovery: Domain Account | Download of `PowerView.ps1`. |
| **Lateral Movement**| T1021.002 | Remote Services: SMB/Windows Admin Shares | `net use Z: \\FILESRV-01\...` |
| **Collection** | T1074.001 | Data Staged: Local Data Staging | Creation of the `\exfiltration\` folder. |
| **Collection** | T1119 | Automated Collection | Use of `Robocopy.exe` for mass copying. |
| **Defense Evasion** | T1070 | Indicator Removal on Host | `net use Z: /delete` (Cleanup). |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol | Use of `nslookup.exe` (DNS) to the C2 domain. |

---

## 🚦 Triage and Handling of False Positives (Alert Fatigue Management)
A crucial part of this investigation was filtering out the noise inherent to native Windows processes. The following alerts were properly classified as False Positives and recommended for *tuning* in the SIEM rules:

*   **TrustedInstaller.exe:** Legitimately started by `services.exe` (Windows Modules Installer).
*   **taskhostw.exe KEYROAMING:** Executed by `svchost.exe`, part of native Windows credential roaming synchronization.
*   **rdpclip.exe:** Standard clipboard process managed by `svchost.exe` during active RDP sessions.
*   **WUDFHost.exe:** Started by `services.exe` to manage user-mode drivers.
*   **svchost.exe -k wsappx -p:** Legitimate service group call for Microsoft Store (UWP) processes.

---

## 🚨 Indicators of Compromise (IOCs)

### Domains and URLs (Network)
*   `trendymillineryco.me`
*   `fashionindustrytrends.xyz`
*   `hatmakereurope.xyz`
*   `modernmillinerygroup.online`
*   `hatventuresworldwide.online`
*   `haz4rdw4re.io` (C2 / DNS Exfiltration Domain)

### Host and Process Artifacts
*   **File:** `ImportantInvoice-Febrary.zip`
*   **File:** `PowerView.ps1`
*   **Path:** `C:\Users\michael.ascot\downloads\exfiltration\`
*   **Malicious Process:** `powershell.exe` (Spawning `nslookup`, `net.exe`, `Robocopy`)

---

## 🛡️ Remediation Actions (Incident Response)

1.  **Containment:** Immediate isolation of the host `win-3450` from the corporate network to interrupt the DNS exfiltration. Disabling of the compromised user account in Active Directory.
2.  **Eradication:** Implementation of permanent blocks at email gateways, web proxies, and DNS Sinkhole for all identified domains (highlighting `haz4rdw4re.io`). Complete purge of inboxes to remove the campaign's emails.
3.  **Recovery & Post-Incident Analysis:** Export of DNS logs to attempt decoding of the requests and determine the exact extent of the data leak (*Data Breach*). Forensic analysis of the staging folder on the compromised host. Tuning of SIEM rules to reduce the false positives identified during the response.
