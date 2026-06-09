# SSH brute-force detection (KQL / Microsoft Sentinel)

A KQL rule that detects SSH brute-force attacks against a Linux host: it flags when a single source IP produces more than 20 failed login attempts in a 5-minute window, surfaced as an incident in Microsoft Sentinel.

## What it detects

SSH brute-force is an attempt to gain access to a machine by repeatedly guessing the login password over SSH, typically using automated tools like Hydra that fire hundreds of attempts against a target's standard password lists. If one source IP produces 20+ failed login attempts in a short window, that's deemed a brute-force attack — it's not a user fumbling their own password. A real user mistake might be 3 or 4 failures from one IP before they remember it correctly; a few failures is a mistake, but 20+ is a threat.

## The query

```kql
Syslog
| where Computer == "victim-splunk"
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Failed password"
| extend src_ip = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize count() by src_ip
| where count_ > 20
```

Pipe by pipe:

- **`Syslog`** — the Log Analytics table that holds the Linux syslog events shipped from the VM. It's where every queried event in this rule comes from.
- **`| where Computer == "victim-splunk"`** — filters the results to only the `victim-splunk` host. Without this, the query would scan and return events from every VM shipping syslog into the workspace — slower, noisier, and unnecessarily costly given Sentinel charges on data ingested.
- **`| where Facility in ("auth", "authpriv")`** — a facility is a category that Linux attaches to each log event when it's written, so events can be filtered later. Both `auth` and `authpriv` carry login-related events — `authpriv` holds the more sensitive ones (like SSH password attempts), and using both ensures the rule catches every login event reliably.
- **`| where SyslogMessage contains "Failed password"`** — filters the results down to only failed authentication events. When SSH rejects a login, the Linux logging service writes a message containing the exact text "Failed password" — so matching that string isolates exactly the events that matter for a brute-force detection.
- **`| extend src_ip = extract(...)`** — creates a new column called `src_ip` by extracting the IP address from inside the message text using a regex pattern. The IP isn't available as its own field by default — it's buried in the log line — so this step pulls it out so the next pipe can group and count by it.
- **`| summarize count() by src_ip`** — tallies up the failed-login events and groups the count by source IP, so instead of a list of every failure, you get one row per unique attacker IP with the total number of attempts next to it.
- **`| where count_ > 20`** — filters the grouped results down to only the source IPs with more than 20 failed attempts in the window. 20 is a tuning trade-off — low enough to catch a real brute force quickly, high enough to ignore a normal user mistyping their password a few times. It could be raised or lowered depending on the environment's baseline.

## Scheduling and severity

The rule is set to run every 5 minutes, looking at the last 5 minutes of data. A single brute-force attack can fire hundreds of attempts per minute — if the rule ran every 15 minutes, an attacker would have three times longer to succeed and potentially move laterally before being caught. Running every 5 minutes incurs slightly more query cost than 15, but the overhead is small at lab scale and detection speed matters more than the marginal cost saving.

The severity is set to Medium rather than High. Without an allowlist for legitimate noisy sources — vulnerability scanners, monitoring services, automated jobs — firing the rule at High would generate false positives and create alert fatigue. Once an allowlist is in place, the severity could be raised to High.

## How to test it

To verify the rule fires against a real attack:

1. Start both VMs (`victim-splunk` and `KaliLinuxVM`) in the Azure portal. Wait ~2 minutes for them to fully boot.

2. From a local terminal, SSH into Kali:

```
   ssh azureuser@<kali-public-ip>
```

3. From the Kali host, run Hydra against the victim's public IP. Let it run for around 60 seconds — enough to exceed the 20-attempt threshold — then `Ctrl + C` to stop:

```
   hydra -l azureuser -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh://<victim-public-ip>
```

4. Wait for the next 5-minute cron tick (the rule runs at `:00`, `:05`, `:10`, etc.), then check **Microsoft Sentinel → Incidents**. A new Medium-severity incident titled *"SSH brute-force..."* should appear, with the attacker's IP listed as the IP entity.
