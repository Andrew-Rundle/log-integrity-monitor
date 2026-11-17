"""
lim.py - Linux Log Integrity Monitor
Detects when someone deletes, truncates, or edits log files to hide an attack.
"""

import hashlib
import json
import os
import sys

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


if __name__ == "__main__":
    config = load_config(sys.argv[1] if len(sys.argv) > 1 else "config.json")
    for path in config["watch_files"]:
        print(path)
        print(json.dumps(fingerprint(path), indent=2))
        print()