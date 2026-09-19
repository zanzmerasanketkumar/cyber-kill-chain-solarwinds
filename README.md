# SolarWinds Cyber Kill Chain Analysis

## Overview

This project analyzes the SolarWinds cyberattack using the Cyber Kill Chain framework.

The investigation maps the attack across the different stages of the Cyber Kill Chain and connects the observed activity with MITRE ATT&CK techniques, SOC detection opportunities, indicators of compromise, and response actions.

## Objectives

- Analyze the SolarWinds supply-chain attack
- Map the attack to the Cyber Kill Chain
- Identify attack techniques and behaviors
- Map relevant activity to MITRE ATT&CK
- Identify SOC detection opportunities
- Identify potential indicators of compromise
- Analyze detection gaps
- Develop a SOC response approach
- Assign evidence-confidence levels to findings

## Attack

**Incident:** SolarWinds Supply-Chain Attack

**Malware:** SUNBURST

**Attack Type:** Supply-chain compromise

## Cyber Kill Chain

The investigation covers:

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives

## MITRE ATT&CK

The investigation maps relevant attack behaviors to applicable MITRE ATT&CK techniques.

The detailed mappings are available in the investigation report.

## SOC Detection Opportunities

The project examines detection opportunities including:

- Network monitoring
- DNS monitoring
- Endpoint monitoring
- Authentication monitoring
- Process monitoring
- File and system monitoring
- Threat intelligence
- SIEM correlation
- IOC detection

## Evidence Confidence

Each major finding is assigned an evidence-confidence level:

- **High** – Explicitly or directly supported by available evidence
- **Medium** – Reasonably supported with limited interpretation
- **Low** – Possible or inferred
- **Not Established** – Insufficient evidence

## Repository Structure

```text
cyber-kill-chain-solarwinds/
│
├── README.md
│
├── report/
│   └── SolarWinds_Cyber_Kill_Chain_Mapping.md
│
└── screenshots/
    ├── kill_chain_mapping.png
    ├── mitre_attack_mapping.png
    └── detection_opportunities.png
