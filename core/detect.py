import os

from .fingerprint import fingerprint


def find_rotated(path, old):
    """Look for the old content in a neighboring file (e.g. syslog -> syslog.1).
    Returns that file's name if found, otherwise None."""
    folder, name = os.path.split(path)
    for other in os.listdir(folder or "."):
        # Only files like syslog.1, syslog-20261117 (skip compressed .gz archives)
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
    """Return a list of (event, detail) findings. Empty list = nothing suspicious."""
    # File didn't exist at the last check
    if not old["exists"]:
        if not new["exists"]:
            new["rotated_to"] = old.get("rotated_to")  # remember, still waiting
            return []
        if old.get("rotated_to"):
            return [("ROTATED", f"new log file created after rotation to {old['rotated_to']}")]
        return [("CREATED", "file appeared")]

    # File is gone
    if not new["exists"]:
        rotated = find_rotated(path, old)
        if rotated:
            new["rotated_to"] = rotated
            return [("ROTATED", f"moved to {rotated}, waiting for new file")]
        return [("DELETED", f"file removed ({old['lines']} lines of log history gone)")]

    events = []

    # A different file is now at this path (e.g. sed -i, mv, rm + recreate)
    if new["inode"] != old["inode"]:
        rotated = find_rotated(path, old)
        if rotated:
            return [("ROTATED", f"rotated to {rotated}")]
        events.append(("REPLACED", f"different file at this path (inode {old['inode']} -> "
                                   f"{new['inode']}), {old['lines']} -> {new['lines']} lines"))
    # Same file, but it got smaller (e.g. truncate -s 0, > file)
    elif new["size"] < old["size"]:
        rotated = find_rotated(path, old)
        if rotated:
            return [("ROTATED", f"copytruncate rotation, old content copied to {rotated}")]
        events.append(("TRUNCATED", f"{old['size']} -> {new['size']} bytes, "
                                    f"{old['lines']} -> {new['lines']} lines"))
    # Same file, but the part that already existed was changed
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