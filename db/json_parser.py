#!/usr/bin/env python3
import sys
import os
import json
import hashlib
import mimetypes
from datetime import datetime

# Optional external libs:
#   pip install tlsh ssdeep
try:
    import tlsh
except ImportError:
    tlsh = None

try:
    import ssdeep
except ImportError:
    ssdeep = None

DB_PATH = "db/file_db.json"


# -----------------------------
# Helpers: load/save DB
# -----------------------------
def load_db(path: str = DB_PATH) -> dict:
    """Load the JSON database from disk, or return an empty dict if it doesn't exist."""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict, path: str = DB_PATH) -> None:
    """Save the JSON database to disk."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4, sort_keys=True)


# -----------------------------
# Lookup functionality
# -----------------------------
def lookup_by_sha256(db: dict, sha256_value: str):
    """
    Separate lookup function, as requested.
    Returns the entry for a given sha256 if it exists, else None.
    """
    return db.get(sha256_value)


# -----------------------------
# Hashing + file metadata
# -----------------------------
def compute_hashes_and_meta(file_path: str) -> dict:
    """
    Compute hashes (sha256, md5, tlsh, ssdeep) and basic metadata for a file.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    # TLSH
    if tlsh is not None:
        try:
            tlsh_hash = tlsh.hash(data)
        except Exception:
            tlsh_hash = ""
    else:
        tlsh_hash = ""

    # ssdeep
    if ssdeep is not None:
        try:
            ssdeep_hash = ssdeep.hash(data)
        except Exception:
            ssdeep_hash = ""
    else:
        ssdeep_hash = ""

    size = len(data)
    file_type, _ = mimetypes.guess_type(file_path)
    if file_type is None:
        file_type = "unknown"

    return {
        "sha256": sha256,
        "md5": md5,
        "tlsh": tlsh_hash,
        "ssdeep": ssdeep_hash,
        "size": size,
        "file_type": file_type,
    }


# -----------------------------
# Update DB with a file
# -----------------------------
def update_db_with_file(file_path: str, db: dict) -> None:
    """
    Given a file path and the DB dict, compute its hashes, check if its SHA256 is
    already in the DB, and update accordingly.

    Requirement:
      - First, check SHA256.
      - If it exists -> stop lookup and only update 'name' (append new filename).
      - If it does not exist -> create a full new entry.
    """
    if not os.path.isfile(file_path):
        print(f"[WARN] Skipping (not a file): {file_path}")
        return

    meta = compute_hashes_and_meta(file_path)
    sha256 = meta["sha256"]
    now_iso = datetime.utcnow().isoformat() + "Z"
    base_name = os.path.basename(file_path)

    existing_entry = lookup_by_sha256(db, sha256)

    if existing_entry is not None:
        # SHA256 already exists -> only update the 'name' list and last_upload_date
        if "name" not in existing_entry or not isinstance(existing_entry["name"], list):
            existing_entry["name"] = []

        if base_name not in existing_entry["name"]:
            existing_entry["name"].append(base_name)

        # We *could* also update last_upload_date logically:
        existing_entry["last_upload_date"] = now_iso

        # No other fields are modified according to your requirement
        return

    # New entry
    db[sha256] = {
        "name": [base_name],
        "size": meta["size"],
        "file_type": meta["file_type"],
        "first_upload_date": now_iso,
        "last_upload_date": now_iso,
        "desc": "",
        "hashes": {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "tlsh": meta["tlsh"],
            "ssdeep": meta["ssdeep"],
        },
    }


# -----------------------------
# Build similarity index
# -----------------------------
def build_similarity_index(db: dict) -> dict:
    """
    From the full DB, build an in-memory JSON-like object of the form:

    {
        "tlsh": {
            "tlsh_1": "sha256_1",
            "tlsh_2": "sha256_2",
            ...
        },
        "ssdeep": {
            "ssdeep_1": "sha256_1",
            ...
        }
    }

    Note: if more than one file has the same tlsh/ssdeep, the later one overwrites
    the previous mapping (simple mapping, as per your example).
    """
    result = {
        "tlsh": {},
        "ssdeep": {},
    }

    for sha256, entry in db.items():
        hashes = entry.get("hashes", {})
        tlsh_val = hashes.get("tlsh", "")
        ssdeep_val = hashes.get("ssdeep", "")

        if tlsh_val:
            result["tlsh"][tlsh_val] = sha256
        if ssdeep_val:
            result["ssdeep"][ssdeep_val] = sha256

    return result


def load_similarity_index(path: str = DB_PATH) -> dict:
    """
    Convenience function:
    - Reads file_db.json
    - Loads it into memory
    - Returns only the similarity index structure described above.
    """
    db = load_db(path)
    return build_similarity_index(db)


# -----------------------------
# -----------------------------
# NEW: Expand arguments (files or directories)
# -----------------------------
def expand_arguments(args):
    """Expands files and directories into a flat list of file paths."""
    expanded = []

    for arg in args:
        if os.path.isfile(arg):
            expanded.append(arg)

        elif os.path.isdir(arg):
            # Add ALL files inside the directory (non-recursive)
            for entry in os.listdir(arg):
                full_path = os.path.join(arg, entry)
                if os.path.isfile(full_path):
                    expanded.append(full_path)

        else:
            print(f"[WARN] Path does not exist: {arg}")

    return expanded


# -----------------------------
# CLI entry point
# -----------------------------
def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        print(f"Usage: {sys.argv[0]} <file1|dir1> [file2|dir2 ...]")
        sys.exit(1)

    # Expand directories → list of files
    file_list = expand_arguments(argv)

    if not file_list:
        print("[ERROR] No valid files found to process.")
        sys.exit(1)

    db = load_db(DB_PATH)

    for file_path in file_list:
        update_db_with_file(file_path, db)

    save_db(db, DB_PATH)
    print(f"[INFO] Updated database saved to {DB_PATH}")

    sim_index = build_similarity_index(db)
    print("[INFO] Similarity index (tlsh + ssdeep):")
    print(json.dumps(sim_index, indent=4))


if __name__ == "__main__":
    main()
