# 🛡️ Microsoft Sentinel SOC Detection Lab

## 📌 Project Overview

This project demonstrates the implementation of a cloud-native Security Operations Center (SOC) monitoring and detection lab using Microsoft Sentinel, Azure Arc, Azure Monitor Agent (AMA), Data Collection Rules (DCR), and Log Analytics Workspace.

The lab collects Windows Security Event Logs from a Windows 11 endpoint, forwards them to Microsoft Sentinel, and uses Kusto Query Language (KQL) to detect suspicious activities such as failed logon attempts, privileged account usage, and credential abuse.

---

## 🏗️ Architecture

```text
Windows 11 Endpoint (Ironhead)
            │
            ▼
       Azure Arc
            │
            ▼
 Azure Monitor Agent
            │
            ▼
 Data Collection Rule
            │
            ▼
 Log Analytics Workspace
            │
            ▼
    Microsoft Sentinel
            │
            ▼
  Analytics Rules & Incidents
```

---

## 🎯 Project Objectives

* Onboard a Windows endpoint into Azure using Azure Arc.
* Deploy Azure Monitor Agent (AMA).
* Configure Data Collection Rules (DCR).
* Collect Windows Security Event Logs.
* Store and analyze logs in Log Analytics Workspace.
* Build custom KQL detections.
* Generate Sentinel incidents.
* Investigate alerts using SOC workflows.
* Map detections to MITRE ATT&CK techniques.

---

## ⚙️ Lab Environment

### Azure Resources

| Resource                | Purpose                      |
| ----------------------- | ---------------------------- |
| Microsoft Sentinel      | SIEM Platform                |
| Log Analytics Workspace | Log Storage & Querying       |
| Azure Arc               | Hybrid Machine Management    |
| Azure Monitor Agent     | Log Collection               |
| Data Collection Rule    | Log Collection Configuration |

### Endpoint

| Component         | Value                           |
| ----------------- | ------------------------------- |
| Hostname          | Ironhead                        |
| Operating System  | Windows 11 Home Single Language |
| Connection Method | Azure Arc                       |
| Region            | Central India                   |

---

## 🔧 Implementation Steps

### 1. Azure Arc Onboarding

The Windows endpoint was onboarded into Azure Arc using the Azure Connected Machine Agent.

After successful onboarding:

* Machine appeared in Azure Arc
* Arc Agent Status = Connected
* Resource Group = SOC
* Location = Central India

---

### 2. Azure Monitor Agent Deployment

The Azure Monitor Agent extension was deployed to the Azure Arc-enabled machine.

Extension:

```text
Azure Monitor Agent for Windows
```

Purpose:

* Collect operating system telemetry
* Forward logs to Azure Monitor
* Enable Sentinel data ingestion

---

### 3. Data Collection Rule Configuration

A Data Collection Rule (DCR) was created and associated with the Azure Arc machine.

#### DCR Details

```text
Name: SOC-Windows-Security-DCR
Region: Central India
Resource Group: SOC
```

#### Resource Association

```text
Machine: Ironhead
```

#### Destination

```text
Log Analytics Workspace: Soc-Lab
```

---

### 4. Security Event Collection

To minimize storage costs while maintaining SOC visibility, only Windows Security Events were collected.

#### XPath Filter

```text
Security!*[System[(band(Keywords,13510798882111488))]]
```

This configuration focuses on audit-related security events and avoids collecting excessive Windows event data.

---

## 📊 Event IDs Observed

The following Windows Security Events were successfully ingested into Sentinel.

| Event ID | Description                      |
| -------- | -------------------------------- |
| 4624     | Successful Logon                 |
| 4625     | Failed Logon                     |
| 4634     | Logoff                           |
| 4648     | Logon Using Explicit Credentials |
| 4672     | Special Privileges Assigned      |
| 4738     | User Account Modified            |
| 5059     | Cryptographic Operation          |
| 5379     | Credential Manager Read          |

---

## 🔍 Sample KQL Queries

### View Recent Security Events

```kql
Event
| where TimeGenerated > ago(30m)
| sort by TimeGenerated desc
| take 50
```

---

### Failed Login Events

```kql
Event
| where EventID == 4625
```

---

### Successful Login Events

```kql
Event
| where EventID == 4624
```

---

### Event ID Summary

```kql
Event
| summarize Count=count() by EventID
| order by Count desc
```

---

## 🚨 Detection Use Case #1

### Multiple Failed Login Attempts

#### Detection Query

```kql
Event
| where EventID == 4625
| summarize FailedAttempts=count() by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

#### Detection Logic

Generate an alert when:

* Three or more failed logons occur
* Within a five-minute window
* On the same host

#### MITRE ATT&CK Mapping

```text
T1110 - Brute Force
```

#### Severity

```text
Medium
```

---

## 🧪 Attack Simulation

To generate failed authentication events:

```cmd
runas /user:FakeUser cmd
```

Entering an invalid password creates Event ID 4625 logs which are forwarded into Sentinel.

---

## 🔎 Investigation Workflow

For each incident:

1. Review alert details.
2. Identify affected host.
3. Determine user account involved.
4. Examine event IDs.
5. Map activity to MITRE ATT&CK.
6. Assess severity.
7. Document findings.
8. Close incident.

---

## 📈 Results

Successfully achieved:

* Azure Arc onboarding
* Azure Monitor Agent deployment
* DCR configuration
* Windows Security Log ingestion
* Log Analytics integration
* Sentinel log visibility
* KQL threat detection
* Failed login detection use case

---

## 🚧 Planned Enhancements

### Detection Rule 2

Privileged Account Usage

```kql
Event
| where EventID == 4672
```

MITRE ATT&CK:

```text
Privilege Escalation
```

---

### Detection Rule 3

Explicit Credential Usage

```kql
Event
| where EventID == 4648
```

MITRE ATT&CK:

```text
Credential Access
```

---

### Future Improvements

* Custom Analytics Rules
* Incident Automation
* Playbooks (SOAR)
* Watchlists
* Threat Hunting Queries
* MITRE ATT&CK Dashboard
* Sentinel Workbooks
* Security Incident Reports

---

## 🛠️ Technologies Used

* Microsoft Sentinel
* Azure Arc
* Azure Monitor Agent
* Azure Monitor
* Log Analytics Workspace
* Kusto Query Language (KQL)
* Windows Event Logs
* Azure Portal

---

## 📚 Skills Demonstrated

* SIEM Operations
* Security Monitoring
* Log Analysis
* Threat Detection
* Incident Investigation
* KQL Query Development
* Azure Security Services
* Windows Event Analysis
* SOC Operations

---

## 👨‍💻 Author

Nikhil Vedpathak

SOC Analyst | Security Operations | Microsoft Sentinel | Azure Security | Threat Detection
