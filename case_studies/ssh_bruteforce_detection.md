# SSH Brute Force Detection with Threat Intelligence Correlation

## 1. Objective

The objective of this detection is to identify SSH brute force activity and correlate the source IP address with a known malicious IP list using Splunk.

---

## 2. Environment

* Splunk Enterprise deployed on Ubuntu Server
* Windows VM configured as log source and forwarder
* Custom threat intelligence lookup table (known_bad_ips.csv)

---

## 3. Data Sources

* Authentication logs containing failed login attempts
* Simulated log data using Splunk SPL
* Lookup table containing known malicious IP addresses

---

## 4. Detection Logic

```spl
| stats count by src_ip
| where count > 5
| lookup known_bad_ips.csv src_ip OUTPUT src_ip AS matched_ip
| where isnotnull(matched_ip)
```

---

## 5. Detection Description

This detection identifies IP addresses generating multiple failed authentication attempts, indicating potential brute force activity. The results are then enriched by correlating the source IP with a predefined list of known malicious IP addresses. Only IPs present in the threat intelligence lookup are returned.

---

## 6. Simulation Methodology

```spl
| makeresults count=10
| eval src_ip="192.168.1.50"
| stats count by src_ip
| where count > 5
| lookup known_bad_ips.csv src_ip OUTPUT src_ip AS matched_ip
| where isnotnull(matched_ip)
```

---

## 7. Results

* Source IP: 192.168.1.50
* Failed Attempt Count: 10
* Threat Intelligence Match: Yes

The detection successfully identified simulated brute force activity and confirmed the IP as malicious based on the lookup table.

---

## 8. Analyst Response

Upon detection, a SOC analyst should:

1. Validate the source IP against external threat intelligence platforms
2. Review authentication logs for targeted accounts
3. Identify affected systems
4. Block the IP at firewall or endpoint level
5. Monitor for repeated activity
6. Escalate if lateral movement or compromise is suspected

---

## 9. Key Learnings

* Implementation of detection logic using SPL
* Use of lookup tables for threat intelligence enrichment
* Simulation of attack scenarios for validation
* Understanding of brute force attack patterns

---

## 10. Conclusion

This project demonstrates the ability to design and validate a real-world detection use case in Splunk by combining behavioral analysis with threat intelligence correlation. The detection pipeline was tested end-to-end using simulated attack data.
