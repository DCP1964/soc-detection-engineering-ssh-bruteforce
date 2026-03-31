# SOC Detection Engineering Project — SSH Brute Force with Threat Intelligence Correlation

---

## Detection Output

### Raw Brute Force Logs
![Raw Logs](screenshots/ssh_bruteforce_raw_logs.png)

### Detection with Threat Intelligence Correlation
![Detection Result](screenshots/detection_correlation_result.png)

## 1. Project Overview

This project demonstrates the design and validation of a Security Operations Center (SOC) detection use case in Splunk. The detection identifies SSH brute force activity and correlates it with a custom threat intelligence dataset.

The implementation focuses on detection engineering principles, including event aggregation, threshold-based detection, and enrichment using lookup tables.

---

## 2. Objectives

- Detect repeated failed authentication attempts indicative of brute force attacks
- Correlate detected activity with known malicious IP addresses
- Simulate attack data to validate detection logic
- Document investigation and response workflow
- Build a structured, reproducible SOC use case

---

## 3. Architecture

### Components

- Splunk Enterprise (Ubuntu Server VM) — SIEM platform
- Windows VM — Log source and data forwarder
- Splunk Universal Forwarder — Log ingestion
- Custom Lookup Table — Threat intelligence simulation

### Data Flow

1. Logs are generated on the Windows system
2. Universal Forwarder sends logs to Splunk Enterprise
3. Splunk indexes and processes the data
4. Detection logic aggregates and filters events
5. Lookup table enriches events with threat intelligence

---

## 4. Data Sources

- Authentication logs (failed login attempts)
- Simulated event data using Splunk SPL
- Threat intelligence lookup (known_bad_ips.csv)

---

## 5. Detection Strategy

### Detection Logic

The detection identifies IP addresses generating multiple failed authentication attempts and correlates them with known malicious IPs.

```spl
index=security sourcetype=linux_secure ("Failed password" OR "authentication failure")
| stats count, values(user) as attempted_users, min(_time) as first_attempt, max(_time) as last_attempt by src_ip
| where count > 10
| lookup known_bad_ips.csv src_ip OUTPUT src_ip AS matched_ip
| where isnotnull(matched_ip)
| eval duration_minutes = round((last_attempt - first_attempt)/60, 2)
```

This query uses a specific index and sourcetype to improve search performance and reduce unnecessary data scanning in Splunk. This approach aligns with best practices for SIEM optimization and cost efficiency.

### WHY THIS DETECTION WORKS

Detection Rationale

This detection is effective because it combines behavioral analysis with threat intelligence correlation. Brute force attacks generate a high volume of failed authentication attempts, which can be identified through aggregation.

By correlating these events with a known malicious IP list, the detection reduces false positives and prioritizes high-confidence threats.

### Advanced Detection: Success After Failure

```
index=security sourcetype=linux_secure
("Failed password" OR "Accepted password")
| eval status=if(searchmatch("Failed password"), "failed", "success")
| stats count(eval(status="failed")) as failed_count,
        count(eval(status="success")) as success_count
        by src_ip
| where failed_count > 5 AND success_count > 0
```

This detection identifies potential account compromise scenarios where a source IP performs multiple failed authentication attempts followed by a successful login.

This pattern is critical in SOC environments as it indicates that an attacker may have successfully guessed or obtained valid credentials.

### MITRE ATT&CK Mapping

- T1110 — Brute Force

### Key Concepts

- Threshold-based detection (count > 5)
- Event aggregation using stats
- Threat intelligence enrichment using lookup
- Noise reduction by filtering only matched IPs

### Detection Tuning Strategy

A static threshold (e.g., count > 5) can lead to false positives in real environments.

In production, thresholds should be dynamically adjusted based on:

- Baseline authentication behavior per user/IP
- Time-of-day patterns
- Standard deviation of login failures

This project uses a fixed threshold for demonstration purposes, but highlights the need for adaptive detection tuning in real SOC environments.

---

## 6. Simulation and Validation

To validate the detection logic, simulated brute force activity was generated.

```spl
| makeresults count=10
| eval src_ip="192.168.1.50"
| stats count by src_ip
| where count > 5
| lookup known_bad_ips.csv src_ip OUTPUT src_ip AS matched_ip
| where isnotnull(matched_ip)
```

Simulated data (192.168.1.50) was used to validate detection logic, while real authentication logs from the environment were analyzed to demonstrate actual brute force behavior.

### Validation Outcome

- Source IP: 192.168.1.50
- Failed Attempts: 10
- Threat Intelligence Match: Confirmed

The detection successfully identified and correlated malicious activity.

---

## 7. Threat Intelligence Automation (Future Enhancement)

The current implementation uses a static CSV lookup table (known_bad_ips.csv) for threat intelligence enrichment.

In a production SOC environment, this process would be automated to ensure real-time accuracy and scalability.

Potential automation approaches include:

- Integration with threat intelligence APIs (e.g., VirusTotal, AlienVault OTX)
- Python scripts to periodically fetch and update malicious IP feeds
- Scheduled tasks or cron jobs to refresh lookup tables in Splunk
- Integration with SIEM threat intelligence platforms

This enhancement would reduce manual effort, improve detection accuracy, and ensure up-to-date threat intelligence correlation.

## 8. Investigation Workflow

Upon detection, the following investigation steps are performed:

1. Validate detection accuracy and threshold
2. Analyze failed authentication logs
3. Identify targeted accounts and systems
4. Check for successful login attempts
5. Correlate with additional activity from the same IP
6. Verify IP reputation using threat intelligence sources

Repeated failed login attempts targeting common usernames (e.g., root, invalid users) indicate automated brute force activity rather than normal user behavior.
---

## 9. False Positive Mitigation

- Exclude known administrative IP addresses (internal networks)
- Tune threshold based on baseline authentication behavior
- Filter service accounts generating expected login failures
- Correlate only with threat intelligence to reduce noise
- Monitor for repeated patterns rather than single events

---

## 10. Response Actions

- Block malicious IP at network level
- Disable or secure targeted accounts
- Enforce stronger authentication controls
- Monitor for repeated or distributed attempts
- Escalate if compromise indicators are present

---
## 11. Detection Limitations

This detection may not identify:

- Distributed brute force attacks (multiple IPs targeting one account)
- Low-and-slow attacks over extended time periods
- Attacks using valid credentials without failed attempts
- This approach aligns with best practices for SIEM optimization and cost efficiency.

---

## 12. Project Structure

```
case_studies/
playbooks/
lookups/
queries/
screenshots/
```

---

## 13. Key Skills Demonstrated

- SPL query development
- Detection engineering
- Threat intelligence integration
- Log analysis and correlation
- SOC investigation methodology
- Security use case validation

---

## 14. Assumptions and Limitations

- Detection is based on simulated and limited log data
- Threshold values may vary in production environments
- Lookup table represents a simplified threat intelligence source
- Index and field names may differ across environments

---

## 15. Future Improvements

- Integrate real authentication logs from Linux systems
- Add geo-location enrichment
- Implement risk-based scoring
- Tune detection thresholds using baseline analysis
- Automate alerting and response workflows

---

## 16. Conclusion

This project demonstrates a complete SOC detection workflow, from data ingestion and detection logic to validation and response. It highlights the practical application of detection engineering techniques using Splunk and provides a reproducible framework for identifying brute force attacks enriched with threat intelligence.

---

## 17. Evidence

Refer to the screenshots directory for detection results and validation output.
