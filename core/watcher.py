import os
import signal
import time
from datetime import datetime

from .alerts import clear_status, color, send_alert, show_status
from .baseline import baseline_path, load_baseline, save_baseline
from .chain import add_to_chain, baseline_hash, chain_path, last_run_event, verify_chain
from .detect import compare
from .fingerprint import fingerprint


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


def run_checks(config, baseline, show_ok):
    """Check every watched file once and update the baseline in memory.
    Returns the number of problems found."""
    problems = 0
    for path in config["watch_files"]:
        old = baseline.get(path, {"exists": False})
        new = fingerprint(path, old_size=old["size"] if old["exists"] else None)

        events = compare(path, old, new)
        if not events and show_ok:
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
    return problems


def check(config):
    """Run one check, save the baseline, print a summary."""
    if not os.path.exists(baseline_path(config)):
        print("No baseline found. Run 'init' first.")
        return

    baseline = load_baseline(config)
    problems = check_own_records(config, baseline)
    problems += run_checks(config, baseline, show_ok=True)
    save_baseline(config, baseline)
    print(f"\n{problems} problem(s) found." if problems else "\nNo tampering detected.")


def file_id(path):
    """(inode, size) of a file - changes if anyone writes to or replaces it."""
    try:
        info = os.stat(path)
        return (info.st_ino, info.st_size)
    except FileNotFoundError:
        return None


def watch(config):
    """Check every few seconds until stopped with Ctrl+C or kill."""
    if not os.path.exists(baseline_path(config)):
        print("No baseline found. Run 'init' first.")
        return

    baseline = load_baseline(config)
    total = check_own_records(config, baseline)

    last = last_run_event(config)
    if last and last["event"] == "START":
        send_alert(config, "ALERT", "MONITOR_GAP", chain_path(config),
                   f"monitor did not shut down cleanly (killed?); logs were unwatched "
                   f"since {last['time']}")
        total += 1
    add_to_chain(config, "START", pid=os.getpid())

    stop = False

    def request_stop(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    interval = config.get("interval_seconds", 3)
    save_every = config.get("checkpoint_seconds", 60)
    print(color("OK", f"Watching {len(config['watch_files'])} files every {interval}s "
                      f"(Ctrl+C to stop)"))
    for path in config["watch_files"]:
        print(f"   - {path}")
    print()

    cycle = 0
    last_save = time.time()
    chain_state = file_id(chain_path(config))

    while not stop:
        cycle += 1

        if file_id(chain_path(config)) != chain_state:
            send_alert(config, "ALERT", "CHAIN_TAMPERED", chain_path(config),
                       "chain.log was changed by something other than lim")
            total += 1

        found = run_checks(config, baseline, show_ok=False)
        total += found


        if found or time.time() - last_save >= save_every:
            save_baseline(config, baseline)
            last_save = time.time()
        chain_state = file_id(chain_path(config))   

        status = color("OK", "all intact") if total == 0 else color("ALERT", f"{total} alert(s) so far")
        show_status(f"{datetime.now().strftime('%H:%M:%S')}  check #{cycle}  {status}")

        wake_up = time.time() + interval
        while not stop and time.time() < wake_up:
            time.sleep(0.2)

    clear_status()
    save_baseline(config, baseline)
    add_to_chain(config, "STOP", pid=os.getpid(), checks=cycle, alerts=total)
    print(f"Stopped cleanly after {cycle} checks, {total} alert(s).")