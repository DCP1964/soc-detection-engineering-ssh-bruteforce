# SSH Brute Force Detection Playbook

## 1. Playbook Objective

This playbook provides a structured response procedure for investigating and responding to SSH brute force activity detected in Splunk and correlated with known malicious IP addresses.

---

## 2. Trigger Conditions

This playbook is triggered when:

* Multiple failed authentication attempts are detected from a single source IP
* The source IP matches an entry in the known malicious IP lookup table

Detection Query:

```spl id="3u0q7y"
| stats count by src_ip
| where count > 5
| lookup known_bad_ips.csv src_ip OUTPUT src_ip AS matched_ip
| where isnotnull(matched_ip)
```

---

## 3. Initial Triage

### 3.1 Validate Alert

* Confirm detection logic and threshold (count > 5)
* Verify that the IP exists in the threat intelligence lookup
* Check timestamp and frequency of events

### 3.2 Identify Source IP

* Extract source IP address
* Determine geolocation (if enrichment available)
* Check if IP is internal or external

---

## 4. Investigation Steps

### 4.1 Analyze Authentication Logs

* Review failed login attempts for the identified IP
* Identify targeted usernames (e.g., root, admin)
* Check for any successful login attempts from the same IP

Example Query:

```spl id="f0d7fh"
index=* ("Failed password" OR "authentication failure")
| search src_ip="192.168.1.50"
```

---

### 4.2 Check Affected Systems

* Identify destination hosts receiving authentication attempts
* Determine if critical systems are targeted

---

### 4.3 Correlate with Additional Activity

* Look for lateral movement indicators
* Check for unusual processes or commands executed after login
* Investigate related events from the same IP

---

### 4.4 Threat Intelligence Validation

* Verify IP reputation using external sources (if available)
* Confirm whether the IP is associated with known attacks

---

## 5. Containment Actions

* Block source IP at firewall or network level
* Disable or secure targeted accounts
* Enforce multi-factor authentication if applicable
* Apply rate limiting or SSH hardening

---

## 6. Eradication and Recovery

* Reset compromised credentials
* Patch and update affected systems
* Review SSH configuration (disable root login, enforce key-based auth)
* Remove unauthorized access if detected

---

## 7. Post-Incident Activities

* Document incident details
* Update detection thresholds if needed
* Add new malicious IPs to lookup table
* Improve monitoring and alerting coverage

---

## 8. Escalation Criteria

Escalate the incident if:

* Successful login is observed after brute force attempts
* Multiple systems are targeted
* Evidence of persistence or lateral movement is found

---

## 9. Key Metrics

* Number of failed login attempts
* Number of affected systems
* Time to detection and response
* Number of blocked IPs

---

## 10. Conclusion

This playbook ensures a consistent and structured approach to handling SSH brute force attacks. It combines detection validation, investigation, containment, and recovery to minimize risk and improve response efficiency.
