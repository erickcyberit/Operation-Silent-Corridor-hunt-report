# 🕵️ 

## 🌟 Table of Contents 🌟

- [🌍 Scenario](#scenario)
- [🎯 Mission](#mission)
- [🚩 Flag 1: ](#flag-1)
- [🚩 Flag 2: ](#flag-2)
- [🚩 Flag 3: ](#flag-3)
- [🚩 Flag 4 - ](#flag-4)
- [🚩 Flag 5 - ](#flag-5)
- [🚩 Flag 6 - ](#flag-6)
- [🚩 Flag 7 - ](#flag-7)
- [🚩 Flag 8 - ](#flag-8)
- [🚩 Flag 9 - ](#flag-9)
- [📊 Conclusion, Investigation Timeline & Key Findings](#conclusion-investigation-timeline--key-findings)
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



---

<a id="flag-3"></a>
# 🚩 Flag 3: 

**Objective:**


**What to Hunt:**


**Hint:**
1. 
<img src="">

**KQL Query Used:**

```

```



---

### 📑 Task: Provide the value of the command utilized to start up the program.

### ✅ Flag 3 Answer:

---

<a id="flag-4"></a>
# 🚩 Flag 

**Objective:**

**What to Hunt:**

**Hints:**
1. 

<img src="">

**KQL Query Used:**

```

```





## Further Analysis


<img src="">


---

### 📑 Task: 
### ✅ Flag 4 

---

<a id="flag-5"></a>
# 🚩 Flag 5 – Registry Persistence Entry

**Objective:**

**What to Hunt:**

**Hint:**
1. 

<img src="">

**KQL Query Used:**

```

```



---

### 📑 Task: Identify the full Registry Path value.

### ✅ Flag 5 Answer: 
---

<a id="flag-6"></a>
# 🚩 Flag 6 -

**Objective:**


**What to Hunt:**


**Hints:**


<img src="">

**KQL Query Used:**

```

```



---

### 📑 Task: 

### ✅ Flag 6 Answer: UpdateHealthTelemetry

---

<a id="flag-7"></a>
# 🚩 Flag 7 – 

**Objective:**

**What to Hunt:**


**Hint:** 


<img src="">

**KQL Query Used:**

```

```

To trace the complete process chain behind the scheduled task creation, I analysed process events on the `anthony-001` device, starting from `2025-05-07T02:00:36.794406Z`. 

The command line identified was:

```

```


---

### 📑 Task: Provide the kill chain.

### ✅ Flag 7 
---

<a id="flag-8"></a>
# 🚩 Flag 8 – 

**Objective:**

**What to Hunt:**


**KQL Query Used:**

```

```


---

### 📑 Task: Provide the timestamp of the leading event that's causing all these mess.

### ✅ Flag 8 Answer: 

---

<a id="conclusion-investigation-timeline--key-findings"></a>
# 📊 Conclusion, Investigation Timeline & Key Findings



---

<a id="flag-9"></a>
# 🚩 Flag 9 -

**Objective:**


**What to Hunt:**


**Hints:**


<img src="">

**KQL Query Used:**

```

```



---






[![Timeline]()
## Key Findings

| Flag | Objective | Key Findings | Flag Answer |
|------|-----------|--------------|-------------|
| **1** | 
| **2** | 
| **3** |  |
| **4** |
| **5** |
| **6** | |
| **7** | 
| **8** | 

<a id="mitre-attck-mapping"></a>
# 🛡️ MITRE ATT&CK Mapping

| ID | MITRE Tactic | MITRE Technique | Description |
|----|--------------|-----------------|-------------|
| 1  | 
| 2  | 
| 3  | 
| 4  |
| 5  | 
| 6  | 
| 7  | 

<a id="remediation"></a>
# 🛠️ Remediation
