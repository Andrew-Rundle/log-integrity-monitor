"""
lim.py - Linux Log Integrity Monitor
Detects when someone deletes, truncates, or edits log files to hide an attack.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime

# Folder this script lives in, so config.json is found no matter where you run it from
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_config(name="config.json"):
    config_path = os.path.join(SCRIPT_DIR, name)
    with open(config_path) as f:
        return json.load(f)

def fingerprint(path):
    # Get file info from Linux (inode, size, owner, permissions, timestamp)
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return {"exists": False}

    sha = hashlib.sha256()
    size = 0
    lines = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")

    return {
        "exists": True,
        "inode": info.st_ino,               
        "size": size,                       
        "lines": lines,
        "hash": sha.hexdigest(),           
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

def main():
    parser = argparse.ArgumentParser(description="Linux Log Integrity Monitor")
    parser.add_argument("-c", "--config", default="config.json", help="config file name")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="save the baseline")
    init.add_argument("--force", action="store_true", help="overwrite existing baseline")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.command == "init":
        cmd_init(config, args.force)

if __name__ == "__main__":
    main()