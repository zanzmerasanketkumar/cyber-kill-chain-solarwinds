# Cyber Kill Chain Mapping – SolarWinds Supply-Chain Attack (SUNBURST)

## 1. Executive Summary

- **Target/Organization:** SolarWinds (software vendor) and, downstream, its customer base including government agencies and private-sector organizations that used SolarWinds Orion software.
- **Threat Actor:** Not explicitly identified in the provided attack summary (no named threat actor or attribution is given).
- **Attack Type:** Software supply-chain compromise.
- **Initial Attack Vector:** Compromise of the SolarWinds software development/build environment, resulting in malicious code (SUNBURST) being embedded in legitimate, digitally signed Orion software updates.
- **Major Impact:** Numerous organizations worldwide installed the trojanized update; in some environments this led to credential theft, lateral movement, access to email systems, and collection of sensitive information.
- **Overall Attack Progression:** The attackers first compromised SolarWinds' build environment, inserted the SUNBURST malware into Orion update packages, and relied on SolarWinds' trusted update-distribution mechanism to deliver the malware broadly. Once installed, SUNBURST executed on victim systems and established command-and-control communication (including DNS-based methods), which the attackers used selectively to conduct further reconnaissance, credential theft, lateral movement, and data collection in chosen environments.

---

## 2. Cyber Kill Chain Mapping

| Stage | Attacker Activity | Technique/Method | Evidence | MITRE ATT&CK | SOC Detection Opportunity |
|---|---|---|---|---|---|
| **Reconnaissance** | Not explicitly identified in the provided attack summary. Reasonable inference: attackers likely researched SolarWinds' build/development environment and customer base to select a high-value distribution channel. | Inferred: research of software supply chain / build infrastructure | Summary states attackers "compromised the software development and build environment," implying prior knowledge of that environment, but no direct recon evidence is given | T1591 (Gather Victim Org Information) – *inferred, not confirmed* | Monitor for unusual external probing of developer/build infrastructure, VPN, and code-repository access attempts |
| **Weaponization** | Inserted malicious code (SUNBURST) into legitimate SolarWinds Orion software updates | Trojanizing a legitimate, digitally signed software build | "The attackers inserted malicious code, later associated with the SUNBURST malware, into legitimate SolarWinds Orion software updates" | T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain) | Software build-integrity monitoring; code-signing verification; anomaly detection in CI/CD pipeline; unexpected build artifact changes |
| **Delivery** | Distributed the trojanized Orion update through SolarWinds' official, trusted software-update mechanism | Abuse of a legitimate software update/distribution channel | "Because the updates were digitally signed and distributed through SolarWinds' normal software-update mechanism, customers installed the compromised software believing it was legitimate" | T1195.002 (Supply Chain Compromise) | Software update integrity checks; hash/signature verification against known-good baselines; monitoring for unexpected outbound connections immediately following update installation |
| **Exploitation** | Malicious code executed automatically once the compromised Orion update was installed by customers | Execution via trusted, signed software (no separate exploit of a vulnerability described) | "After organizations installed the compromised Orion update, the malware could execute on affected systems" | T1195.002; possibly T1204 (User Execution) *inferred*, since installation of the update itself triggered execution | Endpoint monitoring for anomalous process behavior originating from the Orion software immediately post-update |
| **Installation** | Not explicitly detailed in the summary beyond execution and establishment of a foothold. Reasonable inference: SUNBURST persisted on the host as part of/alongside the installed Orion software. | Inferred: persistence tied to the compromised software component itself | "The attackers used this access to establish a foothold in selected victim environments" | T1554 (Compromise Client Software Binary) – *inferred, reasonably supported*; specific persistence mechanism (registry keys, scheduled tasks, services) **Not explicitly identified in the provided attack summary** | EDR monitoring of the Orion software process tree, unexpected child processes, file/registry modifications tied to Orion components |
| **Command & Control** | Compromised systems communicated with attacker-controlled infrastructure, including DNS-based C2 | DNS-based command-and-control communication | "The malware could... communicate with attacker-controlled infrastructure" and "Security researchers later identified... suspicious DNS-based command-and-control communication" | T1071.004 (Application Layer Protocol: DNS) | DNS monitoring for anomalous query patterns, rare/newly-registered domains, beaconing intervals, DNS requests to unusual TLDs |
| **Actions on Objectives** | In selected victim environments: further reconnaissance, credential theft, lateral movement, access to email systems, collection of sensitive information | Post-compromise operations following initial foothold | "In some environments, the attackers performed additional activities such as credential theft, lateral movement, access to email systems, and collection of sensitive information" | T1003 (OS Credential Dumping) *inferred*; T1021 (Remote Services / Lateral Movement) *inferred*; T1114 (Email Collection) *inferred*; T1005 (Data from Local System) *inferred* — all reasonably supported but not itemized with technical specifics in the summary | Authentication monitoring for anomalous logins/privilege use; mailbox access auditing; internal network traffic analysis for lateral movement patterns; DLP/data-access monitoring |

---

## 3. Detailed Stage-by-Stage Analysis

### 3.1 Reconnaissance

The provided summary does not explicitly describe reconnaissance activity. **Not explicitly identified in the provided attack summary.**

As a reasonable inference, compromising a software vendor's build environment at this scale would typically require the attackers to have gathered information about SolarWinds' development infrastructure, source-code repositories, build pipeline, and possibly employee/developer credentials or access points. This is analyst interpretation, not confirmed fact from the summary.

- **What the SOC should monitor (general best practice):** unusual authentication attempts against developer accounts, VPN access from atypical geographies, reconnaissance-style scanning of internal source-code or build systems, and phishing attempts targeting developers — none of which are confirmed in this summary but represent standard recon indicators for supply-chain attacks.

### 3.2 Weaponization

The summary confirms that the attackers gained the ability to alter the legitimate build process: “the attackers inserted malicious code, later associated with the SUNBURST malware, into legitimate SolarWinds Orion software updates.”

- The "weapon" here was not a traditional payload (e.g., exploit + malicious document) but a trojanized, legitimately signed software binary.
- Because the code was embedded directly into an otherwise legitimate, signed build, traditional weaponization indicators (malicious attachments, obfuscated exploit code delivered externally) do not apply in the usual sense.
- **Detection opportunity:** software integrity/build-pipeline monitoring capable of detecting unauthorized code insertion, unexpected changes to source repositories, or unusual build-server activity. This capability is not stated as having existed in the summary — its absence is a key inferred detection gap.

### 3.3 Delivery

“Because the updates were digitally signed and distributed through SolarWinds' normal software-update mechanism, customers installed the compromised software believing it was legitimate.”

- **Delivery method:** the organization's own trusted software-update channel — not phishing, not a malicious attachment, not a compromised website in the traditional sense.
- **Why it was trusted:** valid digital signatures and delivery through the vendor's standard, expected update process meant that neither endpoint security tools nor users had reason to treat the update as suspicious.
- **Detection opportunities:** software-update/patch-management logs correlated with build-integrity baselines; comparison of released binary hashes against a verified known-good build; anomaly detection for unexpected changes in binary size/behavior between update versions.

### 3.4 Exploitation

“After organizations installed the compromised Orion update, the malware could execute on affected systems and communicate with attacker-controlled infrastructure.”

- No separate software vulnerability is described as being exploited; execution occurred simply because the trojanized code was part of the software that IT staff intentionally installed.
- The "weakness" exploited was organizational/process trust in vendor-signed updates rather than a technical vulnerability (e.g., no CVE is cited in the summary).
- **Detection opportunity:** endpoint behavioral monitoring immediately following the Orion update installation — e.g., the Orion process spawning unexpected child processes, initiating unusual outbound network connections, or accessing sensitive files/credentials shortly after update deployment.

### 3.5 Installation

The summary states attackers used the resulting access “to establish a foothold in selected victim environments and conduct further reconnaissance.” Specific installation mechanics (e.g., registry run keys, scheduled tasks, service creation, dropped files) are **Not explicitly identified in the provided attack summary.**

- **Reasonable inference:** since the malicious code was embedded within the legitimate Orion binary itself, the "installation" of the malware was effectively synonymous with the routine installation of the software update — a persistence approach less reliant on conventional standalone persistence artifacts.
- **What should be monitored (general guidance, not confirmed for this case):** unexpected new processes, services, scheduled tasks, or registry modifications associated with the Orion installation directory; unusual file creation timestamps inconsistent with the official release.
- **EDR role:** endpoint detection and response tooling with behavioral analytics could help flag deviation between the expected behavior of the Orion software and its actual runtime behavior post-update, even without a known malware signature.

### 3.6 Command & Control

“The malware could execute on affected systems and communicate with attacker-controlled infrastructure... Security researchers later identified the malicious activity and developed indicators associated with the SUNBURST malware, including suspicious DNS-based command-and-control communication and other behavioral indicators.”

- **Role of DNS:** DNS was used as a C2 communication channel, allowing the malware to blend its traffic with legitimate-looking network activity and evade simpler network-based detections.
- **Suspicious network behavior to detect:** anomalous DNS query volume or patterns from Orion-related hosts, queries to domains with unusual characteristics (e.g., low reputation, recently registered, inconsistent with normal business use), beaconing at regular intervals, and DNS responses used to relay commands.
- **Relevant log sources:** DNS server logs, firewall/proxy logs, IDS/IPS alerts, and SIEM-correlated network flow data.

### 3.7 Actions on Objectives

“In some environments, the attackers performed additional activities such as credential theft, lateral movement, access to email systems, and collection of sensitive information.”

- **Credential theft:** confirmed as an activity type in the summary, though specific technique (e.g., credential dumping tools, Kerberos abuse) is not detailed.
- **Lateral movement:** confirmed generally; specific protocols/tools used are **Not explicitly identified in the provided attack summary.**
- **Email access:** confirmed as an objective in some environments; mechanism not detailed.
- **Sensitive information collection:** confirmed as a general objective; specific data types are not detailed.
- This stage reflects the ultimate strategic goal of the intrusion — consistent with an espionage/intelligence-collection style operation rather than disruptive or ransomware-style objectives, though the summary does not explicitly name the threat actor's motive.

---

## 4. SOC Detection & Response Plan

| Attack Stage | What Should Have Been Detected? | Detection Source | SOC Alert | Immediate Response |
|---|---|---|---|---|
| Reconnaissance | Not explicitly identified in the provided attack summary | N/A | N/A | N/A |
| Weaponization | Unauthorized modification of the Orion build/source code | Build-pipeline integrity monitoring, source-code repository audit logs | Alert on unsigned/unexpected commits or build artifact changes | Isolate build environment; audit recent commits/build jobs; rotate build-system credentials |
| Delivery | Update package hash/signature mismatch against verified baseline | Software update management logs, file-integrity monitoring | Alert on binary hash deviation between releases | Halt further update distribution; quarantine affected update package pending verification |
| Exploitation | Anomalous process/network behavior immediately after Orion update installation | EDR/XDR endpoint telemetry | Alert on Orion process spawning unusual child processes or connections | Isolate affected host; capture forensic image; begin triage |
| Installation | Persistence artifacts tied to Orion components (where present) | EDR, endpoint file/registry monitoring | Alert on unexpected file/registry changes associated with Orion | Contain host; preserve artifacts for forensic analysis |
| C2 | DNS-based beaconing to suspicious/attacker-controlled domains | DNS logs, firewall/proxy logs, IDS/IPS, SIEM correlation | Alert on anomalous DNS query patterns / known-bad domain indicators | Block malicious domains/IPs; isolate communicating hosts; begin network-wide threat hunt |
| Actions on Objectives | Credential theft, lateral movement, mailbox access, sensitive data access | Authentication logs, email audit logs, network traffic analysis, DLP | Alert on abnormal login patterns, privilege escalation, mailbox access anomalies, unusual data transfers | Reset affected credentials; revoke sessions; contain affected accounts/systems; assess scope of data exposure |

---

## 5. Example SOC Detection Opportunities

**SIEM:** Centralized correlation of build-system logs, software update logs, DNS logs, authentication logs, and endpoint telemetry would allow a SOC to connect a seemingly benign software update event to subsequent anomalous DNS and authentication activity — activity that, viewed in isolation, might not trigger alerts.

**EDR/XDR:** Endpoint tooling capable of behavioral baselining could flag the Orion process performing actions inconsistent with its normal function (e.g., unusual outbound connections, unexpected file writes, credential access attempts), even without a malware signature match.

**DNS Monitoring:** Because C2 communication relied on DNS, dedicated DNS analytics (query frequency, entropy analysis of subdomains, rare top-level domains, newly observed domains) represent one of the most promising detection opportunities described in the summary.

**Network Monitoring:** Monitoring for unusual outbound connections from systems running Orion — particularly to infrastructure with no prior established business relationship — could have surfaced C2 activity.

**Threat Intelligence:** Once SUNBURST indicators were published by researchers, retroactive threat-intel matching (domains, hashes, behavioral patterns) allowed defenders to identify prior compromise; proactive threat-intel feeds integrated into SIEM/EDR could reduce time-to-detection in future incidents.

**Software Integrity Monitoring:** Verifying vendor-released binaries against independently maintained hash baselines, and monitoring build environments for unauthorized changes, directly addresses the root-cause weaponization/delivery vector described in the summary.

**Authentication Monitoring:** Given that credential theft and lateral movement occurred in some environments, monitoring for anomalous authentication patterns (impossible travel, privilege escalation, unusual service-account use) is a key control for detecting the Actions on Objectives stage.

---

## 6. SOC Analyst Investigation Workflow

1. Receive and triage the alert (e.g., DNS anomaly or threat-intel match against SUNBURST indicators).
2. Identify potentially affected SolarWinds Orion systems across the environment.
3. Determine the installed software/update version against known-compromised version(s).
4. Examine endpoint telemetry for anomalous Orion process behavior.
5. Search DNS and network logs for suspicious communication patterns.
6. Identify Indicators of Compromise (IOCs) relevant to SUNBURST.
7. Investigate affected user accounts for signs of compromise.
8. Search for evidence of credential theft or lateral movement.
9. Determine whether sensitive information (including email data) was accessed.
10. Isolate affected systems where appropriate to prevent further spread.
11. Block known malicious infrastructure at the firewall/DNS/proxy layer.
12. Remove or replace the compromised software components.
13. Reset potentially compromised credentials.
14. Restore systems from verified, trusted sources/backups.
15. Perform threat hunting across the environment for related, previously undetected activity.
16. Document findings and update detection rules/playbooks to reflect lessons learned.

---

## 7. Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Malware name | SUNBURST |
| Domains | Not provided in the attack summary |
| IP addresses | Not provided in the attack summary |
| URLs | Not provided in the attack summary |
| File hashes | Not provided in the attack summary |
| File names | Not provided in the attack summary |
| Processes | Not provided in the attack summary |
| User accounts | Not provided in the attack summary |
| Network indicators | General reference to "suspicious DNS-based command-and-control communication" — no specific domains/patterns provided |
| Other | Compromised software: SolarWinds Orion (specific version numbers not provided in the attack summary) |

---

## 8. MITRE ATT&CK Mapping

| Observed Behavior | MITRE ATT&CK Technique | Technique ID | Evidence | Status |
|---|---|---|---|---|
| Insertion of malicious code into legitimate software build | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | "Attackers inserted malicious code... into legitimate SolarWinds Orion software updates" | Confirmed |
| Delivery via trusted vendor update mechanism | Supply Chain Compromise | T1195.002 | "Distributed through SolarWinds' normal software-update mechanism" | Confirmed |
| Execution of malware upon update installation | User Execution / Supply Chain-triggered Execution | T1204 (inferred) | "The malware could execute on affected systems" after installation | Reasonably inferred |
| Persistence tied to compromised software component | Compromise Client Software Binary | T1554 | "Establish a foothold in selected victim environments" | Reasonably inferred |
| DNS-based C2 communication | Application Layer Protocol: DNS | T1071.004 | "Suspicious DNS-based command-and-control communication" | Confirmed |
| Credential theft in victim environments | OS Credential Dumping | T1003 | "Credential theft" listed as an observed activity | Confirmed (activity type), technique specifics inferred |
| Lateral movement within victim networks | Remote Services / Lateral Movement (general) | T1021 (inferred) | "Lateral movement" listed as an observed activity | Confirmed (activity type), technique specifics inferred |
| Access to email systems | Email Collection | T1114 (inferred) | "Access to email systems" listed as an observed activity | Confirmed (activity type), technique specifics inferred |
| Collection of sensitive information | Data from Local System / Information Collection | T1005 (inferred) | "Collection of sensitive information" listed as an observed activity | Confirmed (activity type), technique specifics inferred |

---

## 9. Detection Gaps

**1. Supply-chain / software build integrity**
- *What happened:* Malicious code was inserted directly into the SolarWinds build process before distribution.
- *Why it evaded detection:* The resulting binary was digitally signed and delivered through the normal, trusted update process, giving it inherent legitimacy in the eyes of both automated tools and IT staff.
- *Control that could have detected it:* Build-environment integrity monitoring, source-code change auditing, reproducible/verifiable builds.
- *Improvement:* Implement continuous integrity verification of build artifacts and stronger access controls/segmentation around build infrastructure.

**2. Trusted software update channel**
- *What happened:* Customers installed the compromised update believing it legitimate because it came through the vendor's official channel.
- *Why it evaded detection:* Security tools generally treat digitally signed, vendor-distributed updates as inherently trustworthy and do not deeply inspect their behavior.
- *Control that could have detected it:* Independent hash verification of released binaries; behavioral post-installation monitoring rather than trust-based allowlisting alone.
- *Improvement:* Treat vendor software updates as requiring baseline behavioral validation, not blind trust, especially for high-privilege infrastructure software.

**3. Post-compromise behavioral detection**
- *What happened:* The summary notes attackers "attempted to blend their activity with normal network and system behavior," and the compromise went undetected for a significant period before researchers identified it.
- *Why it evaded detection:* Lack of behavioral baselining/anomaly detection meant blended, low-and-slow attacker activity did not stand out from normal operations.
- *Control that could have detected it:* EDR/XDR with behavioral analytics; SIEM correlation rules tuned for anomaly detection rather than signature-only matching.
- *Improvement:* Invest in detection engineering focused on behavioral anomalies and cross-log correlation, not just known-bad indicator matching.

**4. DNS monitoring**
- *What happened:* C2 communication relied on DNS and went undetected until external researchers identified associated indicators.
- *Why it evaded detection:* DNS traffic is frequently under-monitored relative to other network traffic, and attacker DNS communication may closely mimic legitimate patterns.
- *Control that could have detected it:* Dedicated DNS security monitoring/analytics capable of identifying beaconing and anomalous query behavior.
- *Improvement:* Deploy DNS-specific threat detection and integrate DNS logs into central SIEM correlation.

---

## 10. Recommended SOC Improvements

1. **Centralized SIEM monitoring** — correlate build-system, update-distribution, DNS, authentication, and endpoint logs into a single analysis pipeline.
2. **EDR/XDR deployment** — ensure behavioral detection capability on all endpoints, including infrastructure-management software hosts.
3. **DNS monitoring** — deploy dedicated DNS analytics to detect beaconing and anomalous domain activity.
4. **Network traffic analysis** — monitor for unusual outbound connections, particularly from privileged infrastructure-management systems.
5. **Software integrity verification** — independently validate vendor-released binaries against trusted hash baselines.
6. **Secure software development practices** — apply strict code review, least-privilege access, and change-control processes to build pipelines.
7. **Build-environment security** — isolate and harden build/CI-CD infrastructure; enforce multi-factor authentication and strict access logging.
8. **Threat intelligence integration** — ingest and operationalize IOC feeds (e.g., published SUNBURST indicators) into detection tooling.
9. **Continuous threat hunting** — proactively hunt for behavioral indicators of supply-chain compromise rather than relying solely on alerts.
10. **MITRE ATT&CK-based detection engineering** — build detection rules mapped explicitly to techniques such as T1195.002 and T1071.004.
11. **Supply-chain risk management** — maintain a vendor risk-assessment program and require software bill of materials (SBOM) transparency from critical vendors.
12. **Incident response procedures** — maintain playbooks specifically addressing supply-chain compromise scenarios, including rapid update-rollback and vendor-communication protocols.

---

## 11. Final SOC Assessment

Based strictly on the information provided, the earliest realistic detection opportunity was at the **software build/weaponization stage**, where integrity monitoring of the build environment could have identified unauthorized code insertion before distribution. Absent that, the **delivery/exploitation boundary** — verifying update package integrity against trusted baselines — represented a second strong opportunity, since the compromise depended entirely on the update being accepted as trustworthy.

The most significant detection opportunity described in the summary itself is the **DNS-based command-and-control communication**, which is explicitly called out as a behavioral indicator later identified by researchers. This suggests that dedicated DNS monitoring and anomaly detection represent the most concrete, evidence-supported control that could have shortened the detection timeline.

The major detection gaps were: (1) absence of build/software integrity verification, (2) implicit trust placed in signed vendor updates without behavioral validation, and (3) insufficient behavioral/anomaly-based monitoring capable of catching attacker activity deliberately designed to blend in with normal operations.

To reduce the impact of similar attacks in the future, a SOC should prioritize: software supply-chain integrity controls, DNS and network behavioral analytics, EDR/XDR-based endpoint behavioral monitoring, and threat-intelligence-driven detection engineering — layered so that no single point of trust (such as a vendor's digital signature) is sufficient on its own to bypass detection.

*(This assessment is based strictly on the technical details provided in the attack summary and does not attribute the incident to any specific actor, nation, or organization.)*
