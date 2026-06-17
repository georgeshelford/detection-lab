# Detection Lab

> A small Azure detection lab with a Linux victim, Kali as the attacker, and two SIEMs — Microsoft Sentinel and Splunk — catching the same SSH brute-force in parallel.

![Microsoft Sentinel incident page showing the SSH brute-force analytics rule fired at Medium severity against Kali's IP (`20.90.160.254`), mapped to MITRE Credential Access (T1110)](screenshots/Sentinel-Incident.png)

The lab simulates an SSH brute-force attack against an Ubuntu host using Hydra from a Kali attacker VM, and catches the attack independently in two SIEMs — Splunk Enterprise running locally on the victim and Microsoft Sentinel in the cloud. Full architecture, detection rules, and the things I learnt the hard way live in [`/docs`](docs/) and [`/detections`](detections/).

## What's in this repo

| Document | What's in it |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | The end-to-end design: how data flows from a failed SSH login through both SIEMs, explained as a shop-and-burglar story with a Mermaid diagram. |
| [`docs/gotchas.md`](docs/gotchas.md) | Six things I learnt the hard way during the build — NSG priority order, AMA install ≠ collect, the two-VNet trap, and others. |
| [`detections/sentinel/`](detections/sentinel/) | The Sentinel KQL analytics rule with a pipe-by-pipe walkthrough, scheduling rationale, and how to trigger it. |
| [`detections/splunk/`](detections/splunk/) | The Splunk SPL scheduled alert — mirror of the Sentinel rule, currently a placeholder pending a session on the lab Windows machine. |
| [`screenshots/`](screenshots/) | Sanitised proof images: the Sentinel incident, hydra running, Splunk events. |

## Tech stack

**Infrastructure**
- Microsoft Azure (VMs, VNets, NSGs)
- Ubuntu Linux (victim host)
- Kali Linux (attacker host)

**Detection**
- Splunk Enterprise (local, SPL)
- Microsoft Sentinel (cloud, KQL)
- Azure Monitor Agent + Data Collection Rules
- Log Analytics workspace

**Attack tooling**
- Hydra (SSH brute-force, `rockyou.txt` wordlist)
- nmap (reconnaissance)

**Documentation**
- Markdown, Mermaid diagrams

## Context

This lab was built in a sponsored Azure dev tenant with explicit authorisation from the resource owner, for the purpose of personal learning. All attack traffic — including the SSH brute-force simulation — runs against assets I'm authorised to test, inside an environment dedicated to this work.
