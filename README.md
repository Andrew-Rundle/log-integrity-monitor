# Linux Log-Integrity-Monitor

A tool that detects when somone tampers with Linux log files as an attempt to hide an attack. 

**Built and tested on Ubuntu 26.04.** Runs as a `systemd` service. Written in python and only uses standard libary.

## Why this matters

One of the first things that an intruder will do after breaking into a system is erase the evidence. Clearing or editing system logs to cover tracks is a usual technique.

The problem is that logs are constantly changing and new lines are appended all the time. `LIM` solves this by understanding how logs behaving and looking for the suspicious activity.

Existing tooles like AIDE, Tripwire and Samhain mostly treat the log files as files that are expected to change, so they may skip them at times. `LIM` is built for the log case and adds a hash chain so that an attacker can't rewrite the monitors own records.

## What is detected

| Event | Meaning | Example attack |
|-------|---------|----------------|
| `REPLACED` | A different file now sits at the path (new inode) | `sed -i '/evidence/d' auth.log` |
| `TRUNCATED` | The file shrank | `truncate -s 0 auth.log`, `> auth.log` |
| `MODIFIED` | Existing content was changed in place | overwriting bytes with `dd` |
| `DELETED` | A watched log is gone | `rm syslog` |
| `PERMISSIONS` | File mode changed | `chmod 666 kern.log` |
| `OWNERSHIP` | Owner changed | `chown attacker auth.log` |
| `TIMESTAMP` | Modified time moved backwards | `touch -d '2020-01-01'` (timestomping) |
| `MONITOR_GAP` | The monitor was killed and restarted | `pkill -9 lim` |
| `CHAIN_TAMPERED` / `CHAIN_BROKEN` | lim's own records were edited | editing `chain.log` |
| `BASELINE_TAMPERED` | The baseline file was edited | editing `baseline.json` |
| `ROTATED` *(info, not an alert)* | Normal log rotation | `logrotate` |

Normal appending to log lines has no alert and normal `logrotate` activity is recognised and reported as info.

## How it works

`LIM` has three layers, with each one protecting the one before it

```
Log files      ← protected by the BASELINE   (detects tampering with the logs)
Baseline file  ← protected by the CHAIN      (detects tampering with the baseline)
Hash chain     ← protected by itself         (detects tampering with the records)
```

**1. The baseline.** On its initialization `LIM` records a fingerprint of all the watched files containing (SHA-512 hash, size, line count, inode, permissions, owner and timestamp). This is the known "before" snapshot.

**2. Comparison.** During each check, `LIM` re-fingerprints each file. It also just compares the first N bytes where N is the size of recorded at the last check. If the prefix still matches, the old content is untouched and the file just grew, meaning it was a normal append. If the prefixes don't match, the file shrank or inode changes, and `LIM` reports the tampering with classification.

**3. Rotation awareness."" Before alerting that a file was shrunken or replaced `LIM` will check to see if the old content was moved to a neighbor file. If it was, info reported as `ROTATED`, otherwise tampering was involved.

**4. Hash Chain.** Every record `LIM` writes - alerts, baseline saves, start/stop avents - is appended to `chain.log` and includes the hash of the previous record. If any record is edited or deleted then the link breaks and `LIM` sends an alert. The baselines hash is stored in the chain protecting the baseline json from being silently rewritten.

**5. Continuous monitoring.** `watch` mode checks every few seconds, writes `START` and
`STOP` records so a killed monitor is detected on the next run (`MONITOR_GAP`), and alerts
immediately if its own chain file is modified by another process.

 
## Requirements
 
- Linux (developed and tested on Ubuntu)
- Python 3.8+ (standard library only — no `pip install` needed)
- `root` privileges (system logs and `/var/lib/lim` are root-only)
---
 
## Installation
 
```bash
git clone https://github.com/Andrew-Rundle/log-integrity-monitor.git
cd log-integrity-monitor
sudo bash install.sh
```

 
```bash
systemctl status lim
journalctl -u lim -f      # watch alerts live
```

To remove the service

```bash
sudo bash uninstall.sh
```

## Demo
 
A scripted demo runs each attack one at a time so you can watch `lim` react. Use two
terminals:
 
```bash
# Terminal 1 — the monitor
journalctl -u lim -f
 
# Terminal 2 — the attacks
sudo bash demo/attack.sh --manual     
```