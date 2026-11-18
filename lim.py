#!/usr/bin/env python3
"""
lim.py - Linux Log Integrity Monitor
Detects when someone deletes, truncates, or edits log files to hide an attack.
"""

import sys
import argparse
import hashlib
import json
import os
from datetime import datetime

try:
    import syslog          
except ImportError:
    syslog = None

# Folder this script lives in, so config.json is found no matter where you run it from
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_config(name="config.json"):
    config_path = os.path.join(SCRIPT_DIR, name)
    with open(config_path) as f:
        return json.load(f)

def fingerprint(path, old_size=None):
    # Get file info from Linux (inode, size, owner, permissions, timestamp)
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return {"exists": False}

    sha = hashlib.sha256()
    size = 0
    lines = 0
    old_part_hash = None
    if old_size == 0:
        old_part_hash = sha.hexdigest()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            if old_part_hash is None and old_size is not None and size + len(chunk) >= old_size:
                cut = old_size - size
                sha.update(chunk[:cut])
                old_part_hash = sha.hexdigest()  # hash of the first old_size bytes
                sha.update(chunk[cut:])
            else:
                sha.update(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")

    return {
        "exists": True,
        "inode": info.st_ino,               
        "size": size,                       
        "lines": lines,
        "hash": sha.hexdigest(),
        "old_part_hash": old_part_hash,    
        "mode": oct(info.st_mode & 0o777),  
        "owner": info.st_uid,              
        "mtime": info.st_mtime,             
    }

def baseline_path(config):
    return os.path.join(config["state_dir"], "baseline.json")

def save_baseline(config, files):
    os.makedirs(config["state_dir"], exist_ok=True)
    #Makes folder on accessible from root
    os.chmod(config["state_dir"], 0o700)

    data = {"saved": datetime.now().isoformat(timespec="seconds"), "files": files}
    path = baseline_path(config)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)
    add_to_chain(config, "BASELINE", baseline_hash=baseline_hash(files))

def load_baseline(config):
    with open(baseline_path(config)) as f:
        return json.load(f)["files"]


def cmd_init(config, force):
    if os.path.exists(baseline_path(config)) and not force:
        print("A baseline already exists. Use 'init --force' to replace it.")
        return

    print("Taking baseline...\n")
    files = {}
    for path in config["watch_files"]:
        fp = fingerprint(path)
        files[path] = fp
        if fp["exists"]:
            print(f"  OK       {path}  ({fp['size']} bytes, {fp['lines']} lines, "
                  f"hash {fp['hash'][:12]}...)")
        else:
            print(f"  MISSING  {path}")

    save_baseline(config, files)
    print(f"\nBaseline saved to {baseline_path(config)}")

def find_rotated(path, old):
    """Look for the old content in a neighboring file. Returns that file's name if found, otherwise None."""
    folder, name = os.path.split(path)
    for other in os.listdir(folder or "."):
        if other == name or not other.startswith(name) or other.endswith(".gz"):
            continue
        candidate = os.path.join(folder, other)
        if not os.path.isfile(candidate) or os.path.getsize(candidate) < old["size"]:
            continue
        # Is the old log content still intact at the start of this file?
        if fingerprint(candidate, old_size=old["size"])["old_part_hash"] == old["hash"]:
            return other
    return None

def compare(path, old, new):

    # File didn't exist before this check
    if not old["exists"]:
        if not new["exists"]:
            new["rotated_to"] = old.get("rotated_to")  
            return []
        if old.get("rotated_to"):
            return [("ROTATED", f"new log file created after rotation to {old['rotated_to']}")]
        return [("CREATED", "file appeared")]

    # File is deleted
    if not new["exists"]:
        rotated = find_rotated(path, old)
        if rotated:
            new["rotated_to"] = rotated
            return [("ROTATED", f"moved to {rotated}, waiting for new file")]
        return [("DELETED", f"file removed ({old['lines']} lines of log history gone)")]

    events = []

    # File at this path is different
    if new["inode"] != old["inode"]:
        rotated = find_rotated(path, old)
        if rotated:
            return [("ROTATED", f"rotated to {rotated}")]
        
        events.append(("REPLACED", f"different file at this path (inode {old['inode']} -> " f"{new['inode']}), {old['lines']} -> {new['lines']} lines"))
    # File decreased in size 
    elif new["size"] < old["size"]:
        rotated = find_rotated(path, old)
        if rotated:
            return [("ROTATED", f"copytruncate rotation, old content copied to {rotated}")]
        events.append(("TRUNCATED", f"{old['size']} -> {new['size']} bytes, " f"{old['lines']} -> {new['lines']} lines"))
    
    # Same file but the hash that already existed changed
    elif new["old_part_hash"] != old["hash"]:
        events.append(("MODIFIED", "earlier log content was changed in place"))

    # Metadata tampering
    if new["mode"] != old["mode"]:
        events.append(("PERMISSIONS", f"{old['mode']} -> {new['mode']}"))
    if new["owner"] != old["owner"]:
        events.append(("OWNERSHIP", f"owner uid {old['owner']} -> {new['owner']}"))
    if new["mtime"] < old["mtime"]:
        events.append(("TIMESTAMP", "modified time moved backwards (faked with touch -d?)"))

    return events

COLORS = {"ALERT": "\033[1;31m", "INFO": "\033[36m", "OK": "\033[32m"} 
RESET = "\033[0m"
USE_COLOR = sys.stdout.isatty()  
GENESIS = "0" * 64

def color(level, text):
    return f"{COLORS[level]}{text}{RESET}" if USE_COLOR else text

def chain_path(config):
    return os.path.join(config["state_dir"], "chain.log")


def record_hash(record):
    """SHA-256 of a record's contents (everything except its own hash)."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

def baseline_hash(files):
    """SHA-256 of the baseline contents, so we can tell if baseline.json was edited."""
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()

def last_record(config):
    try:
        with open(chain_path(config)) as f:
            lines = [line for line in f if line.strip()]
        return json.loads(lines[-1]) if lines else None
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def add_to_chain(config, event, **data):
    """Append a record that is linked to the previous one by its hash."""
    last = last_record(config)
    record = {
        "seq": last.get("seq", 0) + 1 if last else 1,      
        "time": datetime.now().isoformat(timespec="seconds"),
        "event": event,
        **data,
        "prev": last.get("hash", GENESIS) if last else GENESIS,  
    }
    record["hash"] = record_hash(record)
    os.makedirs(config["state_dir"], exist_ok=True)
    with open(chain_path(config), "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    os.chmod(chain_path(config), 0o600)
    return record

def verify_chain(config):
    """Walk the whole chain. Returns (list of problems, last recorded baseline hash)."""
    if not os.path.exists(chain_path(config)):
        return ["chain file is missing"], None

    problems = []
    prev = GENESIS
    expected_seq = 1
    last_baseline = None
    with open(chain_path(config)) as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"line {n}: unreadable (corrupted)")
                prev = None
                continue
            if record.get("seq") != expected_seq:
                problems.append(f"line {n}: expected record #{expected_seq} but found "
                                f"#{record.get('seq')} (records deleted or inserted)")
            if prev is not None and record.get("prev") != prev:
                problems.append(f"line {n}: link to the previous record is broken")
            if record_hash(record) != record.get("hash"):
                problems.append(f"line {n}: record #{record.get('seq')} was altered")
            if "baseline_hash" in record:
                last_baseline = record["baseline_hash"]
            prev = record.get("hash")
            expected_seq = (record.get("seq") or expected_seq) + 1
    return problems, last_baseline

def check_own_records(config, files):
    """Before trusting the baseline, make sure nobody tampered with our records."""
    problems, last_baseline = verify_chain(config)
    found = 0
    if problems:
        send_alert(config, "ALERT", "CHAIN_BROKEN", chain_path(config), "; ".join(problems[:3]))
        found += 1
    if last_baseline and baseline_hash(files) != last_baseline:
        send_alert(config, "ALERT", "BASELINE_TAMPERED", baseline_path(config),
                   "baseline.json does not match the hash recorded in the chain")
        found += 1
    return found

def send_alert(config, level, event, path, detail):
    """Report a finding in 3 places: terminal, alert log file, and syslog."""
    record = add_to_chain(config, event, level=level, path=path, detail=detail)
    message = f"[{level}] {event} {path}: {detail} (chain #{record['seq']} {record['hash'][:12]})"

    print(color(level, f"  {level:<6} {event:<12}") + f" {path}: {detail}")

    alert_log = config.get("alert_log")
    if alert_log:
        try:
            with open(alert_log, "a") as f:
                f.write(f"{datetime.now().isoformat(timespec='seconds')} {message}\n")
        except OSError as e:
            print(f"  (could not write to {alert_log}: {e})")

    if syslog and config.get("use_syslog", True):
        priority = syslog.LOG_WARNING if level == "ALERT" else syslog.LOG_INFO
        syslog.openlog("lim", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(priority, message)

def cmd_check(config):
    if not os.path.exists(baseline_path(config)):
        print("No baseline found. Run 'init' first.")
        return

    baseline = load_baseline(config)
    problems = check_own_records(config, baseline)

    for path in config["watch_files"]:
        old = baseline.get(path, {"exists": False})
        new = fingerprint(path, old_size=old["size"] if old["exists"] else None)

        events = compare(path, old, new)
        if not events:
            grew = new.get("size", 0) - old.get("size", 0)
            if not new["exists"]:
                note = "(still missing)"
            elif grew > 0:
                note = f"(+{grew} bytes appended)"
            else:
                note = "(unchanged)"
            print(color("OK", "  OK    ") + f" {path} {note}")

        for event, detail in events:
            if event == "ROTATED":  
                send_alert(config, "INFO", event, path, detail)
            else:
                send_alert(config, "ALERT", event, path, detail)
                problems += 1

        # The current state becomes the new known-good baseline
        new.pop("old_part_hash", None)
        baseline[path] = new

    save_baseline(config, baseline)
    print(f"\n{problems} problem(s) found." if problems else "\nNo tampering detected.")

def cmd_verify(config):
    """Read-only audit: checks the chain, the baseline, and the files. Changes nothing."""
    print("Hash chain:")
    problems, last_baseline = verify_chain(config)
    if problems:
        for p in problems:
            print(color("ALERT", "  FAIL  ") + p)
    else:
        print(color("OK", "  OK    ") + f"{last_record(config)['seq']} records, all links intact")

    print("Baseline:")
    if not os.path.exists(baseline_path(config)):
        print(color("ALERT", "  FAIL  ") + "baseline.json is missing")
        return
    files = load_baseline(config)
    if last_baseline and baseline_hash(files) == last_baseline:
        print(color("OK", "  OK    ") + "matches the hash recorded in the chain")
    else:
        problems.append("baseline")
        print(color("ALERT", "  FAIL  ") + "does NOT match the chain (baseline.json was edited)")

    print("Log files:")
    for path in config["watch_files"]:
        old = files.get(path, {"exists": False})
        new = fingerprint(path, old_size=old["size"] if old["exists"] else None)
        events = [e for e in compare(path, old, new) if e[0] != "ROTATED"]
        if not events:
            print(color("OK", "  OK    ") + path)
        for event, detail in events:
            problems.append(event)
            print(color("ALERT", f"  {event:<12}") + f" {path}: {detail}")

    print(color("ALERT", f"\n{len(problems)} problem(s) found.") if problems
          else color("OK", "\nEverything verified."))

def main():
    parser = argparse.ArgumentParser(description="Linux Log Integrity Monitor")
    parser.add_argument("-c", "--config", default="config.json", help="config file name")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="save the baseline")
    init.add_argument("--force", action="store_true", help="overwrite existing baseline")
    sub.add_parser("check", help="compare files to the baseline")
    sub.add_parser("verify", help="read-only audit of the chain, baseline, and files")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.command == "init":
        cmd_init(config, args.force)
    elif args.command == "check":
        cmd_check(config)
    elif args.command == "verify":
        cmd_verify(config)

if __name__ == "__main__":
    main()