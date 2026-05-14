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
# 🚩 Flag 1: 

**Objective:**


**What to Hunt:**


**Hints:**
1. 

<img src="">

<img src="">

**KQL Query Used:**

```

```


## Earliest File Appearance — 


<img src="">

**KQL Query Used:**

```

```



---

### 📑 Task: 

### ✅ Flag 

---

<a id="flag-2"></a>
# 🚩 Flag 2:

**Objective:**


**What to Hunt:**


**Hints:**
1. 

<img src="">

**KQL Query Used:**

```

```



---

### 📑 Task: Provide the name of the program in question.

### ✅ Flag 2 

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
# 🚩 Flag 7 – Process Spawn Chain

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


**Thought:**


---

### 📑 Task: Provide the timestamp of the leading event that's causing all these mess.

### ✅ Flag 8 Answer: 

---

<a id="conclusion-investigation-timeline--key-findings"></a>
# 📊 Conclusion, Investigation Timeline & Key Findings










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
