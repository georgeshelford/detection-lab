# SSH brute-force detection (SPL / Splunk)

> **Coming soon.** This is the Splunk-side mirror of the Sentinel detection in `../sentinel/`. The detection logic is the same — fail-count grouped by source IP with a threshold — implemented as a scheduled alert in Splunk Enterprise running every 15 minutes against the same `auth.log` data the Sentinel rule consumes.
>
> The SPL query and full write-up will be added when I next have access to the lab Windows machine. The schedule difference between the two SIEMs (Splunk 15-min vs Sentinel 5-min) is a deliberate trade-off — Splunk's free-tier license has scheduling limits, while Sentinel's workspace handles the tighter cadence.
