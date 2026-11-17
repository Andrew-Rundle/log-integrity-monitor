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


def color(level, text):
    return f"{COLORS[level]}{text}{RESET}" if USE_COLOR else text


def send_alert(config, level, event, path, detail):
    """Report a finding in 3 places: terminal, alert log file, and syslog."""
    message = f"[{level}] {event} {path}: {detail}"

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
    problems = 0

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


def main():
    parser = argparse.ArgumentParser(description="Linux Log Integrity Monitor")
    parser.add_argument("-c", "--config", default="config.json", help="config file name")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="save the baseline")
    init.add_argument("--force", action="store_true", help="overwrite existing baseline")
    sub.add_parser("check", help="compare files to the baseline")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.command == "init":
        cmd_init(config, args.force)
    elif args.command == "check":
        cmd_check(config)

if __name__ == "__main__":
    main()