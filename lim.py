#!/usr/bin/env python3
"""
lim.py - Linux Log Integrity Monitor
Detects when someone deletes, truncates, or edits log files to hide an attack.
"""

import argparse
import json
import os

from core.alerts import color
from core.baseline import baseline_path, load_baseline, save_baseline
from core.chain import baseline_hash, last_record, verify_chain
from core.detect import compare
from core.fingerprint import fingerprint
from core.watcher import check, watch

# Folder this script lives in, so config.json is found no matter where you run it from
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_config(name="config.json"):
    with open(os.path.join(SCRIPT_DIR, name)) as f:
        return json.load(f)


def cmd_init(config, force):
    """Fingerprint every watched file and save it as the known-good baseline."""
    if os.path.exists(baseline_path(config)) and not force:
        print("A baseline already exists. Use 'init --force' to replace it.")
        return

    print("Taking baseline...\n")
    files = {}
    for path in config["watch_files"]:
        fp = fingerprint(path)
        fp.pop("old_part_hash", None)
        files[path] = fp
        if fp["exists"]:
            print(f"  OK       {path}  ({fp['size']} bytes, {fp['lines']} lines, "
                  f"hash {fp['hash'][:12]}...)")
        else:
            print(f"  MISSING  {path}")

    save_baseline(config, files)
    print(f"\nBaseline saved to {baseline_path(config)}")


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
    sub.add_parser("check", help="compare files to the baseline once")
    sub.add_parser("watch", help="monitor continuously")
    sub.add_parser("verify", help="read-only audit of the chain, baseline, and files")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.command == "init":
        cmd_init(config, args.force)
    elif args.command == "check":
        check(config)
    elif args.command == "watch":
        watch(config)
    elif args.command == "verify":
        cmd_verify(config)


if __name__ == "__main__":
    main()