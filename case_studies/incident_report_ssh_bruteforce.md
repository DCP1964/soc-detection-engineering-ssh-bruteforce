# Incident Report: SSH Brute Force Attack

## 1. Incident Summary

A potential SSH brute force attack was detected based on repeated failed authentication attempts from a single external IP address. The activity was correlated with a known malicious IP from the internal threat intelligence dataset.

---

## 2. Detection Details

* Detection Name: SSH Brute Force with Threat Intelligence Correlation
* Detection Time: [Insert Timestamp]
* Source IP: 192.168.1.50
* Failed Attempts: 10
* Threat Intelligence Match: Yes

---

## 3. Initial Assessment

The source IP generated multiple failed login attempts exceeding the defined threshold (count > 5). Correlation with the threat intelligence lookup confirmed the IP as potentially malicious.

This behavior is consistent with automated brute force attacks targeting SSH services.

---

## 4. Investigation Findings

* Multiple failed authentication attempts observed
* Targeted usernames include common administrative accounts (e.g., root)
* No successful login observed during the timeframe
* No evidence of lateral movement or persistence

---

## 5. Risk Assessment

* Threat Level: Medium
* Likelihood of Compromise: Low (no successful login observed)
* Impact: Potential risk to exposed SSH services

---

## 6. Actions Taken

* Source IP identified and validated
* Detection confirmed as true positive
* Recommendation to block IP at network level

---

## 7. Recommendations

* Implement account lockout policies
* Enforce multi-factor authentication
* Disable direct root login via SSH
* Monitor for repeated attempts from other IPs
* Update threat intelligence lookup with new indicators

---

## 8. Lessons Learned

* Correlation with threat intelligence improves detection accuracy
* Threshold-based detection helps identify brute force patterns
* Continuous monitoring is required to detect distributed attacks

---

## 9. Conclusion

The detection successfully identified and validated a simulated SSH brute force attack. The use of threat intelligence correlation reduced false positives and improved confidence in the alert.
