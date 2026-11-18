import hashlib
import os


def fingerprint(path, old_size=None):
    """Measure a file. If old_size is given, also hash just the first
    old_size bytes (the part that existed at the last check)."""
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

    # Read the file in 1 MB chunks, feeding it into SHA-256 and counting lines
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            # If the old size ends inside this chunk, grab the hash at exactly that point
            if old_part_hash is None and old_size is not None and size + len(chunk) >= old_size:
                cut = old_size - size
                sha.update(chunk[:cut])
                old_part_hash = sha.hexdigest()  
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