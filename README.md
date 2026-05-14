# 🕵️ 

## 🌟 Table of Contents 🌟

- [🌍 Scenario](#scenario)
- [🎯 Mission](#mission)
- [🚩 Flag 1](#flag-1)
- [🚩 Flag 2](#flag-2)
- [🚩 Flag 3](#flag-3)
- [🚩 Flag 4 ](#flag-4)
- [🚩 Flag 5 ](#flag-5)
- [🚩 Flag 6 ](#flag-6)
- [🚩 Flag 7 ](#flag-7)
- [🚩 Flag 8 ](#flag-8)
- [🚩 Flag 9 ](#flag-9)
- [📊 Conclusion](#conclusion-investigation-timeline--key-findings)
- [🛡️ MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [🛠️ Remediation](#remediation)

---

<a id="scenario"></a>
## 🌍 Scenario
"The BfV advisory landed this morning. GREY VEIL has been hitting defence contractors across Europe. Extended dwell times. Previous victims didn't know they were compromised until the intelligence services told them."

"Hofmann wants us to prove we're clean. Or prove we're not. Either way, I need evidence. Start with remote access. That's the entry point in every previous GREY VEIL case. If they're inside, find them. If they're not, prove it. Don't assume either way."


<a id="mission"></a>
## 🎯 Mission

This is a proactive hunt. There are no alerts. No indicators of compromise have been provided. You are hunting based on the advisory alone. Determine whether GREY VEIL has accessed Haldric Aerospace infrastructure. If they have, scope the full extent of the compromise.

**Known Information:**
💻 GREY VEIL // Known Tradecraft
Assessed to operate on behalf of a foreign intelligence service. Previous intrusions against defence, aerospace, and critical infrastructure sectors. The following tradecraft has been observed in prior campaigns:

Extended dwell times measured in weeks, not days
Targeting of remote access infrastructure for initial entry
Preference for techniques that blend with normal administrative activity
Multi-host operations across engineering and infrastructure segments
Interest in intellectual property related to defence programmes
GREY VEIL does not deploy custom tooling. Previous victims reported no malware detections, no endpoint alerts, and no signatures fired during the entire intrusion lifecycle. Traditional detection failed.

<a id="flag-1"></a>
# 🚩 Flag 1: Environment Access

**Objective:**
Confirm access. What is the Sentinel custom log table name?

**What to Hunt:**
Look for the main table name


**Hints:**
1. The table name is in the briefing page and data dictionary.

<img width="957" height="445" alt="image" src="https://github.com/user-attachments/assets/adcc5a2f-4f19-4617-bd31-fecf3fb33408" />


**KQL Query Used:**

```
| where isnotempty(EventTime) | where TimeGenerated > datetime(2026-04-07T14:00:00Z) | summarize count() by MdeTable

```
### ✅ Flag 1 Answer: SilentCorridorX_CL
---

<a id="flag-2"></a>
# 🚩 Flag 2: Suspicious Account

**Objective:**
HUNT LEAD: "The advisory says previous victims were compromised through remote access infrastructure. Profile every account. Find the one that doesn't fit."

**What to Hunt:**
Look at every profile and see which one is suspicious.

**Hints:**
1. Start with remote access logs. Profile every user. One doesn't fit.

**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where todatetime(EventTime) between (
    datetime(2026-02-20T00:00:00Z) ..
    datetime(2026-03-05T23:59:59Z)
)
| where AccountDomain == "HALDRIC"
| where ActionType == "LogonSuccess"

```
This log shows that a remote IP was used to login successfully with an elevated token from s.brandt.

<img width="486" height="430" alt="image" src="https://github.com/user-attachments/assets/d50f6854-df40-4c77-b1f7-5f17d01614e0" />

✅ Flag 2 Answer: s.brandt 

---

<a id="flag-3"></a>
# 🚩 Flag 3: 

**Objective:**
HUNT LEAD: "Could be a busy employee. Could be someone else using their credentials. Prove it one way or the other."

**What to Hunt:**
Find account logins and see if any Remote IP looks suspicious

**Hints:**
1. Check for failed authentication attempts before the first successful session.

**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| project EventTime, AccountName, RemoteIP, TunnelIP, ActionType, DestinationHost
| sort by EventTime asc

<img width="1079" height="25" alt="image" src="https://github.com/user-attachments/assets/31c0fbd9-a6f3-4ea4-bb37-816ae3bdc155" />


```
✅ Flag 3 Answer: 185.220.101.34

The IP address 185.220.101.34 is using an elevated token and belongs to the tor network IP address.

---

<a id="flag-4"></a>
# 🚩 Flag 4 Connection Footprint

**Objective:**

HUNT LEAD: "That IP failed then succeeded. Scope the full picture for this account across the window."

**What to Hunt:**

**Hints:**
1. Count unique source addresses for this account across the investigation window.


**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct EventTime, AccountName, RemoteIP, TunnelIP, ActionType, DestinationHost
| order by EventTime asc


```
<img width="1143" height="25" alt="image" src="https://github.com/user-attachments/assets/c1f4655e-5d1f-4320-ac06-abf92bbc5a0e" />
<img width="1085" height="23" alt="image" src="https://github.com/user-attachments/assets/d9cb1e29-6483-43e3-9225-ede0ddbaded6" />
<img width="1044" height="29" alt="image" src="https://github.com/user-attachments/assets/9d817c8c-f2ac-45f8-b88c-d1e3b7322335" />
<img width="1135" height="21" alt="image" src="https://github.com/user-attachments/assets/ab446639-5f84-43c5-bb3c-48a6477ef975" />


✅ Flag 4 Answer: 4
There are 4 different IP addresses associated with this account.
---

<a id="flag-5"></a>
# 🚩 Flag 5 – Source Address Inventory

**Objective:**
HUNT LEAD: "Need them for threat intel. Pull every distinct source for this account."

**What to Hunt:**
Check every IP address on the account and sort them

**Hint:**
1. Pull all unique source IPs for this account and sort them.


**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct EventTime, AccountName, RemoteIP, TunnelIP, ActionType, DestinationHost
| order by EventTime asc

```

✅ Flag 5 Answer: 45.153.160.88,88.153.72.14,91.234.33.126,185.220.101.34 	
These are the 4 IP addresses in s.brandt 

---

<a id="flag-6"></a>

# 🚩 Flag 6 - Internal Landing Point

**Objective:**
HUNT LEAD: "Threat intel confirms three of those are anonymisation infrastructure. The fourth is residential.

**What to Hunt:**


**Hints:**
1. VPN sessions connect to an internal destination. Check where the attacker's sessions terminated.


<img src="">

**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct EventTime, AccountName, RemoteIP, TunnelIP, ActionType, DestinationHost
| order by EventTime asc

```
<img width="1308" height="149" alt="image" src="https://github.com/user-attachments/assets/8e005b99-054b-435b-9577-fe20a0ae6d18" />



✅ Flag 6 Answer: WS-ENG04

The destination host for failed and successful attempts was WS-ENG04 based on the suspicious IP being 185.220.101.34

---

<a id="flag-7"></a>
# 🚩 Flag 7 – Initial Process

**Objective:**
HUNT LEAD: "Pivot to the beachhead. What's the first non-routine process under their session, and what spawned it?"

**What to Hunt:**
Finding the first command used in DeviceProcessEvents.


**Hint:** 
1. Process events show both the file and the parent that spawned it. Filter for the compromised account on the beachhead, sort by time.


**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where todatetime(EventTime) between (
    datetime(2026-02-15T00:00:00Z) ..
    datetime(2026-02-27T23:59:59Z)
)
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project AccountName, ProcessCommandLine, EventTime, InitiatingProcessFileName

```
<img width="1044" height="58" alt="image" src="https://github.com/user-attachments/assets/a2d8f328-32e2-4b31-9d92-bb3ccc63e9ec" />

The first command used on the account was systeminfo and the parent file is cmd.exe on the earliest EventTime.

✅ Flag 7 Answer: systeminfo.exe/cmd.exe


---

<a id="flag-8"></a>
# 🚩 Flag 8 – Directory Enumeration

**Objective:**
HUNT LEAD: "What did they go after first? If they're mapping the environment, I need to know what they found."

**Hint**
1. Look for AD enumeration commands on the beachhead.

**What to Hunt:**
Find out what the attackers went after first once gaining access to the account.

**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where todatetime(EventTime) between (
    datetime(2026-02-15T00:00:00Z) ..
    datetime(2026-02-27T23:59:59Z)
)
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project AccountName, ProcessCommandLine, EventTime, InitiatingProcessFileName

```

<img width="877" height="209" alt="image" src="https://github.com/user-attachments/assets/df3a8cd7-d449-42d2-84bf-3a3d86460995" />


✅ Flag 8 Answer: Domain Admins, Enterprise Admins

The attackers used the command net group "Domain Admins" /dom and net group "Enterprise Admins" /dom to find out more information.


---

<a id="conclusion-investigation-timeline--key-findings"></a>
# 📊 Conclusion, Investigation Timeline & Key Findings



---

<a id="flag-9"></a>
# 🚩 Flag 9 - Network Reconnaissance

**Objective:**
HUNT LEAD: "They know who the admins are. What infrastructure did they map next?"

**What to Hunt:**
Look for a command where they targeted another asset.

**Hints:**
1. Check DNS and network events originating from the beachhead.



**KQL Query Used:**

```
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where todatetime(EventTime) between (
    datetime(2026-02-15T00:00:00Z) ..
    datetime(2026-03-05T23:59:59Z)
)
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project AccountName, ProcessCommandLine, EventTime, InitiatingProcessFileName
```


<img width="1564" height="47" alt="image" src="https://github.com/user-attachments/assets/b98901ca-fe55-4527-98c6-cd48368a1ee1" />
<img width="1578" height="51" alt="image" src="https://github.com/user-attachments/assets/af5e0c33-dd61-4dd3-a317-6b87a57de692" />


This shows that SRV-DC01 and SRV-FILES02 were being attempted access to in the command line.

✅ Flag 9 Answer: SRV-DC01, SRV-FILES02

---
<a id ="Conclusion"></a>
# Conclusion





<a id="mitre-attck-mapping"></a>
# 🛡️ MITRE ATT&CK Mapping

VPN access via compromised credentials (T1133, T1078)
Use of TOR infrastructure for operational security (T1090)
Landing on engineering workstation WS-ENG04 (T1021)
Host reconnaissance using systeminfo.exe (T1082)
Active Directory privilege enumeration (T1069.002)
Internal network/server reconnaissance (T1018, T1046)

<a id="remediation"></a>
# 🛠️ Remediation

1. Disable and Reset the Compromised Account
Disable or reset the HALDRIC\s.brandt account immediately
- Force password rotation
- Revoke all active VPN and authentication sessions
- Invalidate cached tokens and Kerberos tickets
- Review recent MFA enrollment or authentication changes


2. Isolate the Compromised Host
- Remove WS-ENG04 from the network
- Preserve forensic evidence before rebuilding or reimaging
- Capture memory and disk artifacts if possible
- Review the host for persistence mechanisms or unauthorized access


3. Block Malicious Infrastructure

Block the identified external IP addresses at perimeter devices and VPN gateways:

- 185.220.101.34
- 45.153.160.88
- 88.153.72.14
- 91.234.33.126

Additional actions:

- Block TOR exit-node traffic where operationally feasible
- Review firewall and VPN logs for additional related infrastructure


4. Strengthen Remote Access Security
- Enforce MFA on all VPN and remote access services
- Require phishing-resistant MFA where possible
- Disable legacy authentication protocols
- Restrict VPN access to approved geographic regions if applicable


5. Audit Privileged Access
Review membership of:
- Domain Admins
- Enterprise Admins
- Remove unnecessary privileged accounts
- Implement least-privilege access controls
- Consider Just-In-Time (JIT) or Privileged Access Management (PAM)


6. Hunt for Additional Compromised Accounts

Review authentication activity for:

- Failed-to-successful login patterns
- TOR or anonymized infrastructure usage
- Multiple source IPs for a single account
- Unusual login times or geolocations
- Additional VPN accounts exhibiting similar behavior


7. Improve Detection Capabilities

Create detections and alerts for:

- systeminfo.exe
- net group
- whoami
- nltest
- net user
- ipconfig
- PowerShell enumeration activity
- Suspicious command-line execution from VPN-connected hosts

8. Enhance VPN Monitoring

Deploy monitoring for:

- VPN logins from TOR infrastructure
- Multiple IP addresses associated with one account
- Elevated token logins from unusual locations
- Repeated failed authentication attempts followed by success

9. Increase Logging and Retention
- Enable advanced Defender telemetry
- Enable process command-line logging
- Centralize VPN, endpoint, and identity logs into Microsoft Sentinel
- Increase retention periods to support long dwell-time investigations

10. Harden Internal Infrastructure
- Segment engineering workstations from critical servers
- Restrict workstation-to-server communication
- Audit SMB, RDP, and WinRM access
- Disable unused remote management protocols
Limit administrative share access

11. Conduct a Wider Compromise Assessment
Because the activity aligns with stealth-focused espionage tradecraft:

- Review historical authentication activity
- Investigate potential lateral movement
- Search for evidence of data staging or exfiltration
- Validate integrity of sensitive aerospace project repositories
= Perform enterprise-wide threat hunting for related activity
