import json
import os
from datetime import datetime

from .chain import add_to_chain, baseline_hash


def baseline_path(config):
    return os.path.join(config["state_dir"], "baseline.json")


def save_baseline(config, files):
    # Keep the records in a private folder only root can open (0o700)
    os.makedirs(config["state_dir"], exist_ok=True)
    os.chmod(config["state_dir"], 0o700)

    data = {"saved": datetime.now().isoformat(timespec="seconds"), "files": files}
    path = baseline_path(config)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)  


    add_to_chain(config, "BASELINE", baseline_hash=baseline_hash(files))


def load_baseline(config):
    with open(baseline_path(config)) as f:
        return json.load(f)["files"]