import sys
from datetime import datetime

from .chain import add_to_chain

try:
    import syslog         
except ImportError:
    syslog = None          

COLORS = {"ALERT": "\033[1;31m", "INFO": "\033[36m", "OK": "\033[32m"}  
RESET = "\033[0m"
USE_COLOR = sys.stdout.isatty()   

status_shown = False   


def color(level, text):
    return f"{COLORS[level]}{text}{RESET}" if USE_COLOR else text


def show_status(text):
    """Print watch mode's one-line status, overwriting the previous one."""
    global status_shown
    if sys.stdout.isatty():
        print(f"\r{text}   ", end="", flush=True)
        status_shown = True


def clear_status():
    """Erase the status line so an alert can print cleanly."""
    global status_shown
    if status_shown:
        print("\r" + " " * 79 + "\r", end="")
        status_shown = False


def send_alert(config, level, event, path, detail):
    """Report a finding in 3 places: terminal, alert log file, and syslog."""

    record = add_to_chain(config, event, level=level, path=path, detail=detail)
    message = f"[{level}] {event} {path}: {detail} (chain #{record['seq']} {record['hash'][:12]})"


    clear_status()
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