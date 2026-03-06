# 🔎 SOC Investigation Lab – Brute Force Attack Detection Using Splunk

## 📌 Overview

This lab simulates a **Security Operations Center (SOC) investigation** where an alert for potential brute force activity was triggered.  
Using **Splunk SIEM**, I analyzed Linux authentication logs to determine whether the alert represented a **true security incident or a false positive**.

The investigation focused on identifying:

- Failed login attempts
- Invalid user enumeration attempts
- Successful authentication events

Through log analysis, I confirmed that the alert was a **True Positive**, as the attacker successfully gained access to a user account after multiple login attempts.

---

# 🚨 Alert Information

| Field | Value |
|------|------|
| Alert Name | Brute Force Activity Detection |
| Time | 17/09/2025 – 09:00:21 |
| Target Host | tryhackme-2404 |
| Source IP | 10.10.242.248 |
| Log Source | Linux Secure Logs |
| Index | linux-alert |

---

# 🧠 Initial Alert Assessment

The alert indicated a possible **SSH brute force attack** targeting the Linux host **tryhackme-2404**.

One notable observation was that the **source IP address (10.10.242.248)** is a **private internal IP address**. This suggests several possibilities:

- The attacker already has **internal network access**
- The attacker compromised another **internal system**
- The attacker connected through a **VPN**

To validate whether the alert was legitimate, I began analyzing the **Linux authentication logs stored in Splunk**.
---

# 🔍 Step 1 – Identify Authentication Activity

## Query

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248 
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time
This search retrieves authentication-related events associated with the source IP address 10.10.242.248.

The query filters log messages containing:
-Accepted password for → successful login attempts

-Failed password for → failed login attempts

-Invalid user → attempts using usernames that do not exist

-Sorting the results chronologically using sort + _time helps visualize the sequence of login attempts during the investigation period.

Findings:

The results showed:

-A large volume of authentication attempts

-Multiple attempts targeting invalid usernames

-Repeated login attempts from the same IP address

-Login attempts using invalid usernames suggest that the attacker was likely attempting user enumeration, a common technique used before performing a brute force attack.

# 🔍 Step 2 – Identify Targeted User Accounts

index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username

This query extracts important fields from raw Linux authentication logs and aggregates login attempts by username
-The rex command parses the raw log events to extract the following fields:

-log_hostname → the system generating the log

-action → login result (Failed or Accepted)

-username → account targeted in the login attempt

-src_ip → source IP address

# 🔍 Step 3 – Determine if the Attack Was Successful

index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username

Findings

The results revealed that:

-The account john.smith had both Failed and Accepted login attempts.

-This confirms that the attacker successfully logged into the system after multiple brute force attempts.

# 📊 Final Analysis

Based on the investigation:

-The attacker performed hundreds of login attempts

-The attacker attempted to enumerate users

-The account john.smith was specifically targeted

-A successful SSH login occurred after multiple failed attempts

-This confirms the alert represents a True Positive brute force attack.
