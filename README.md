# 🕵️ 

## 🌟 Table of Contents 🌟

- [🌍 Scenario](#scenario)
- [🎯 Mission](#mission)
- [🚩 Flag 1: ](#flag-1-identify-the-fake-antivirus-program-name)
- [🚩 Flag 2: ](#flag-2-malicious-file-written-somewhere)
- [🚩 Flag 3: ](#flag-3-execution-of-the-program)
- [🚩 Flag 4 - ](#flag-4---keylogger-artifact-written)
- [🚩 Flag 5 - ](#flag-5---registry-persistence-entry)
- [🚩 Flag 6 - ](#flag-6---daily-scheduled-task-created)
- [🚩 Flag 7 - ](#flag-7---process-spawn-chain)
- [🚩 Flag 8 - ](#flag-8---timestamp-correlation)
- [📊 Conclusion, Investigation Timeline & Key Findings](#conclusion-investigation-timeline--key-findings)
- [🛡️ MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [🛠️ Remediation](#remediation)

---

## 👉 [Explore the interactive timeline of key CTF findings here.]()

<a id="scenario"></a>
## 🌍 Scenario



<a id="mission"></a>
## 🎯 Mission



**Known Information:**
💻 DeviceName: 

<a id="flag-1-identify-the-fake-antivirus-program-name"></a>
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

<a id="flag-2-malicious-file-written-somewhere"></a>
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

<a id="flag-3-execution-of-the-program"></a>
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

<a id="flag-4---keylogger-artifact-written"></a>
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

<a id="flag-5---registry-persistence-entry"></a>
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

<a id="flag-6---daily-scheduled-task-created"></a>
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

<a id="flag-7---process-spawn-chain"></a>
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

<a id="flag-8---timestamp-correlation"></a>
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
