# Gotchas — Things I learnt the hard way

This document is a log of the things that didn't go to plan while building the lab. Each one started as a confusing problem and ended with a small lesson — the kind you only learn by hitting them yourself. These are the gotchas I'd carry forward into a real SOC.

## 1. NSG rule priority order

I assumed that adding a tight NSG allow rule would just take effect — write the rule, traffic flows, done. It didn't. Turns out a broader pre-existing rule with a lower priority number was matching first, and the engine never reached the rule I'd added. NSG rules are evaluated strictly in priority order — lowest number wins and the first match is applied, so if a rule isn't doing what you expect, check whether something lower-priority is matching first.

## 2. `source` vs `sourcetype` in Splunk

I assumed `source` and `sourcetype` were interchangeable in Splunk. Running `sourcetype="/var/log/auth.log"` returned zero results — not an error, just nothing — which made me think the data hadn't been ingested when actually the query was wrong. `source` is **where** the data came from (here, the file path `/var/log/auth.log`); `sourcetype` is **what kind** of data it is, a category (`linux_secure`) telling Splunk how to parse it. The lesson: zero results in Splunk often means the query is wrong, not the data, and the field name distinction is small but absolute.

## 3. nmap `filtered` state

I assumed that getting `filtered` results when running `nmap` against `victim-splunk` meant the VM itself was down. I went digging on the host — checking `sshd`, checking config, checking processes — but the service was running fine. What was actually stopping me was that `nmap`'s source IP wasn't on the NSG allowlist, so the scan packets were being silently dropped. The lesson: `filtered` doesn't mean something is down — it means something is blocking me and I can't tell what. Check the network path before debugging the host.

## 4. The two-VNet trap

I assumed that two VMs on separate VNets could talk to each other across the network. They can't — they need to either be on the same VNet, or have VNet peering set up between them. I tried to reach `victim-splunk` from `KaliLinuxVM` using its private IP, couldn't, and spent time troubleshooting before realising the two networks weren't connected at all. As a workaround, I used `victim-splunk`'s public IP instead, which is why the attack travels over the public internet in this lab. The lesson: Azure creates a fresh VNet by default for every VM unless you explicitly pick an existing one, and two VNets aren't connected unless you peer them.

## 5. Kali admin username

When deploying `KaliLinuxVM` from the Azure Marketplace, I set the admin username to `kaliadmin` during deployment. SSH'ing in as `kaliadmin` failed every time, and I assumed the password was wrong before realising the issue was the username itself: the Azure Kali Marketplace image hard-codes the admin user to `azureuser`, ignoring what the deployment form asked for. The lesson: cloud platforms don't always honour what the deployment form said they would — verify the actual admin user post-deployment via `/etc/passwd`, or just try `azureuser` first on any Azure Linux image.

## 6. AMA install ≠ collect

When I created the DCR, `AMA` auto-installed onto `victim-splunk`. I then went to my workspace, ran `Syslog | take 10`, and got nothing back — which led to a brief panic where I assumed `AMA` wasn't working at all. Eventually I re-opened the DCR and realised `auth` and `authpriv` weren't ticked on the Data Sources tab; `AMA` was installed and running fine, but it had no instructions to act on. The lesson: "agent installed" ≠ "data flowing." The agent and the collection config are independent — you have to verify **both** before assuming the pipeline is broken.
