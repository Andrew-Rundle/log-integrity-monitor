import hashlib
import json
import os
from datetime import datetime

GENESIS = "0" * 64  


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
    """The most recent valid record (skips junk lines an attacker may have added)."""
    try:
        with open(chain_path(config)) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    for line in reversed(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "hash" in record and "seq" in record:
            return record
    return None


def add_to_chain(config, event, **data):
    """Append a record that is linked to the previous one by its hash."""
    last = last_record(config)
    record = {
        "seq": last["seq"] + 1 if last else 1,           
        "time": datetime.now().isoformat(timespec="seconds"),
        "event": event,
        **data,
        "prev": last["hash"] if last else GENESIS,       
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
            if not isinstance(record, dict) or "hash" not in record or "seq" not in record:
                problems.append(f"line {n}: not a lim record (inserted by someone else)")
                continue
            if record["seq"] != expected_seq:
                problems.append(f"line {n}: expected record #{expected_seq} but found "
                                f"#{record['seq']} (records deleted or inserted)")
            if prev is not None and record.get("prev") != prev:
                problems.append(f"line {n}: link to the previous record is broken")
            if record_hash(record) != record["hash"]:
                problems.append(f"line {n}: record #{record['seq']} was altered")
            if "baseline_hash" in record:
                last_baseline = record["baseline_hash"]
            prev = record["hash"]
            expected_seq = record["seq"] + 1
    return problems, last_baseline


def last_run_event(config):
    """Find the most recent START or STOP record (used to detect a killed monitor)."""
    last = None
    try:
        with open(chain_path(config)) as f:
            for line in f:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and record.get("event") in ("START", "STOP"):
                    last = record
    except FileNotFoundError:
        pass
    return last