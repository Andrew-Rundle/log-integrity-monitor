#!/bin/bash
# =============================================================================
# demo/attack.sh - live demo for lim (Linux Log Integrity Monitor)
#
# Runs each log-tampering action that lim detects, one at a time, pausing a few
# seconds after each so you can read lim's output in the other window.


AUTH=/var/log/auth.log
SYSLOG=/var/log/syslog
KERN=/var/log/kern.log
STATE_DIR=/var/lib/lim
CHAIN=$STATE_DIR/chain.log
BACKUP_DIR=/var/backups/lim-demo
WATCH_SECS=5            

RED='\033[1;31m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; GREEN='\033[1;32m'
DIM='\033[2m'; RESET='\033[0m'

MANUAL=0

# ----------------------------------------------------------------- helpers ---
need_root() {
    if [ "$EUID" -ne 0 ]; then echo "Run with sudo: sudo bash demo/attack.sh"; exit 1; fi
}

title() {
    echo
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${RESET}"
    echo -e "${CYAN}  Scene $1: $2${RESET}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${RESET}"
}

expect() { echo -e "  ${GREEN}Expect:${RESET} $*"; }

before() {   # pause before running the action, so you can introduce it
    if [ "$MANUAL" -eq 1 ]; then
        read -rp "$(echo -e "  ${DIM}[Enter] to run${RESET} ")" _
    fi
}

after() {    # pause after, so the watch window has time to react
    if [ "$MANUAL" -eq 1 ]; then
        read -rp "$(echo -e "  ${DIM}[Enter] for the next scene${RESET} ")" _
    else
        echo -e "  ${DIM}(watch the lim window for $WATCH_SECS s...)${RESET}"
        sleep "$WATCH_SECS"
    fi
}

run() { echo -e "  ${YELLOW}\$ $1${RESET}"; bash -c "$1"; }

settle() {   # let lim record new lines as the baseline before we tamper with them
    echo -e "  ${DIM}(letting lim record these lines first...)${RESET}"
    sleep "$WATCH_SECS"
}

# ------------------------------------------------------------------ scenes ---
scene_1() {
    title 1 "Add normal log lines (should NOT alert)"
    expect "no alert - appending to a log is normal"
    before
    run "logger 'demo: routine message 1'"
    run "logger 'demo: routine message 2'"
    after
}

scene_2() {
    title 2 "Force a log rotation (should NOT alert)"
    expect "INFO ROTATED - lim finds the old content preserved in syslog.1"
    before
    run "logrotate -f /etc/logrotate.d/rsyslog"
    after
}

scene_3() {
    title 3 "Delete matching lines from auth.log with sed -i"
    run "logger -p auth.info 'demo: marker line AAA'"
    settle
    expect "${RED}REPLACED${RESET} - sed -i swaps in a new file (new inode), lines drop"
    before
    run "sed -i '/marker line AAA/d' $AUTH"
    after
}

scene_4() {
    title 4 "Overwrite bytes inside syslog in place"
    run "logger 'demo: marker line BBB'"
    settle
    expect "${RED}MODIFIED${RESET} - same file, but earlier content changed"
    before
    run "OFF=\$(grep -abo 'marker line BBB' $SYSLOG | head -n1 | cut -d: -f1); \
         printf 'ZZZZZZZ' | dd of=$SYSLOG bs=1 seek=\$OFF conv=notrunc status=none; \
         echo '  (overwrote the marker at byte '\$OFF')'"
    after
}

scene_5() {
    title 5 "Truncate syslog to zero"
    expect "${RED}TRUNCATED${RESET} - file shrank, no copy of the old content exists"
    before
    run "truncate -s 0 $SYSLOG"
    after
}



scene_6() {
    title 6 "Make kern.log world-writable with chmod"
    expect "${RED}PERMISSIONS${RESET} - mode changed (e.g. 0o640 -> 0o666)"
    before
    run "chmod 666 $KERN"
    after
}

scene_7() {
    title 7 "Delete syslog entirely"
    expect "${RED}DELETED${RESET} - watched file is gone"
    before
    run "rm -f $SYSLOG"
    after
}

scene_8() {
    title 8 "Kill the lim monitor"
    if systemctl is-active --quiet lim 2>/dev/null; then
        expect "systemd restarts lim in ~5s, then it reports ${RED}MONITOR_GAP${RESET}"
        before
        run "pkill -9 -f 'lim.py watch'"
        echo -e "  ${DIM}(systemd should restart it automatically...)${RESET}"
        sleep 8
    else
        expect "on the NEXT 'watch' start, lim reports ${RED}MONITOR_GAP${RESET}"
        echo -e "  ${DIM}lim is not running as a service here; start 'watch' again to see it.${RESET}"
        before
        run "pkill -9 -f 'lim.py watch' || echo '  (no running watch process found)'"
    fi
    after
}

scene_9() {
    title 9 "Tamper with lim's own records (the hash chain)"
    expect "${RED}CHAIN_TAMPERED${RESET} while running; 'verify' pinpoints the record"
    before
    run "echo '{\"fake\":\"injected record\"}' >> $CHAIN"
    after
}

scene_10() {
    title 10 "Run a read-only audit"
    expect "a report of the chain, the baseline, and each watched file"
    before
    if [ -f /opt/lim/lim.py ]; then
        run "python3 /opt/lim/lim.py verify || true"
    else
        run "python3 \"$(cd "$(dirname "$0")/.." && pwd)/lim.py\" verify || true"
    fi
    after
}

# ----------------------------------------------------------------- backup ----
backup_logs() {
    mkdir -p "$BACKUP_DIR"
    for f in "$AUTH" "$SYSLOG" "$KERN"; do
        [ -f "$f" ] && cp -a "$f" "$BACKUP_DIR/$(basename "$f").orig" 2>/dev/null
    done
}

cleanup() {
    need_root
    echo "Repairing logs and resetting lim..."
    rm -f /var/log/auth.log.1 /var/log/syslog.1 /var/log/kern.log.1 2>/dev/null
    rm -f /var/log/*.gz 2>/dev/null
    systemctl restart rsyslog 2>/dev/null
    chmod 640 "$KERN" 2>/dev/null
    chown syslog:adm "$AUTH" "$SYSLOG" "$KERN" 2>/dev/null
    logger 'demo: logs restored'
    if systemctl list-unit-files 2>/dev/null | grep -q '^lim.service'; then
        systemctl stop lim 2>/dev/null
        rm -rf "$STATE_DIR"
        python3 /opt/lim/lim.py init 2>/dev/null
        systemctl start lim 2>/dev/null
        echo "Service reset and restarted."
    else
        rm -rf "$STATE_DIR"
        echo "Removed $STATE_DIR. Run 'sudo python3 lim.py init' before the next demo."
    fi
    echo "Cleanup done."
}

list_scenes() {
    grep -E '^\s+title [0-9]+' "$0" | sed -E 's/.*title ([0-9]+) "([^"]*)".*/  \1. \2/'
}

# ------------------------------------------------------------------- main -----
case "$1" in
    --list)    list_scenes; exit 0 ;;
    --cleanup) cleanup; exit 0 ;;
    --manual)  MANUAL=1; shift ;;
esac
[ "$1" = "--manual" ] && { MANUAL=1; shift; }

need_root
echo "lim demo - backing up current logs to $BACKUP_DIR"
backup_logs
echo "Run 'sudo bash demo/attack.sh --cleanup' afterwards to restore."

ONLY="$1"
for n in 1 2 3 4 5 6 7 8 9 10; do
    [ -n "$ONLY" ] && [ "$ONLY" != "$n" ] && continue
    "scene_$n"
done

echo
echo -e "${GREEN}Demo complete.${RESET} Reset with: sudo bash demo/attack.sh --cleanup"