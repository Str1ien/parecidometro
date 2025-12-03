#!/usr/bin/env python3
"""
JSON Database Parser and Generator Module

This module provides functionality to generate and manage a JSON-based file database
with similarity hashes (TLSH and ssdeep) for file comparison and malware analysis.

The database stores file metadata, traditional hashes (SHA256, MD5), and similarity
hashes for efficient file correlation and variant detection.

Main Functions:
    - load_db: Load database from disk
    - save_db: Save database to disk
    - update_db_with_file: Add or update a file in the database
    - build_similarity_index: Create fast lookup index for similarity searches
    - main: CLI entry point for batch processing

Database Structure:
    {
        "sha256_hash": {
            "name": ["filename1.exe", "filename2.exe"],
            "size": 12345,
            "file_type": "application/x-dosexec",
            "first_upload_date": "2025-12-03T12:00:00Z",
            "last_upload_date": "2025-12-03T12:30:00Z",
            "desc": "Optional description",
            "hashes": {
                "sha256": "abc123...",
                "md5": "def456...",
                "tlsh": "T1ABC...",
                "ssdeep": "192:..."
            }
        }
    }

Usage:
    # Process files in a directory
    python3 db/json_parser.py /path/to/files/

    # Process specific files
    python3 db/json_parser.py file1.exe file2.pdf

Dependencies:
    - tlsh: Trend Micro Locality Sensitive Hash (optional)
    - ssdeep: Context-triggered piecewise hashing (optional)
    - FileProcessor: From managers.file_processor

Authors:
    - Alain "Str1ien" Villagrasa
    - Daniel "Kifixo" Huici
    - Razvan "Razvi" Raducu

License: MIT License
Date: December 2025
"""

import sys
import os
import json
import hashlib
from datetime import datetime

# Import FileProcessor for consistent file handling
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from managers.file_processor import FileProcessor

# Optional external libraries
try:
    import tlsh
except ImportError:
    tlsh = None
    print("[WARN] tlsh library not found. TLSH hashing will be disabled.")

try:
    import ssdeep
except ImportError:
    ssdeep = None
    print("[WARN] ssdeep library not found. ssdeep hashing will be disabled.")

DB_PATH = "db/file_db.json"


# -----------------------------
# Helpers: load/save DB
# -----------------------------
def load_db(path: str = DB_PATH) -> dict:
    """
    Load the JSON database from disk.

    Reads the file database from the specified path and returns it as a
    Python dictionary. If the file doesn't exist, returns an empty dictionary.

    Args:
        path (str): Path to the JSON database file (default: db/file_db.json)

    Returns:
        dict: Database contents as {sha256: {metadata, hashes, ...}}
              Returns empty dict {} if file doesn't exist

    Raises:
        JSONDecodeError: If the file exists but contains invalid JSON

    Example:
        >>> db = load_db("db/file_db.json")
        >>> print(f"Database has {len(db)} entries")
        Database has 150 entries
    """
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict, path: str = DB_PATH) -> None:
    """
    Save the JSON database to disk.

    Writes the database dictionary to disk as formatted JSON with indentation
    and sorted keys for better readability and version control.

    Args:
        db (dict): Database dictionary to save
        path (str): Destination path for the JSON file (default: db/file_db.json)

    Returns:
        None

    Raises:
        IOError: If unable to write to the specified path
        PermissionError: If insufficient permissions to write file

    Side Effects:
        Creates or overwrites the file at the specified path

    Example:
        >>> db = {"abc123": {"name": ["file.exe"], "size": 1234}}
        >>> save_db(db, "db/file_db.json")
        # File is written to disk
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4, sort_keys=True)


# -----------------------------
# Lookup functionality
# -----------------------------
def lookup_by_sha256(db: dict, sha256_value: str):
    """
    Look up a file entry by its SHA256 hash.

    Performs a direct dictionary lookup to find if a file with the given
    SHA256 hash exists in the database.

    Args:
        db (dict): The database dictionary
        sha256_value (str): SHA256 hash to look up (64-character hex string)

    Returns:
        dict | None: File entry dictionary if found, None otherwise

    Example:
        >>> db = load_db()
        >>> entry = lookup_by_sha256(db, "abc123...")
        >>> if entry:
        ...     print(f"Found: {entry['name']}")
        ... else:
        ...     print("File not in database")
    """
    return db.get(sha256_value)


# -----------------------------
# Hashing + file metadata
# -----------------------------
def compute_hashes_and_meta(file_path: str) -> dict:
    """
    Compute all hashes and metadata for a file.

    This function performs comprehensive file analysis:
    1. Reads the raw file data
    2. Detects file type using FileProcessor
    3. Processes content (extracts text from PDFs/DOCX, uses raw for binaries)
    4. Calculates traditional hashes (SHA256, MD5) on raw data
    5. Calculates similarity hashes (TLSH, ssdeep) on processed content

    The dual-hashing approach ensures:
    - Traditional hashes identify exact file matches
    - Similarity hashes detect variants and related files

    Args:
        file_path (str): Path to the file to analyze

    Returns:
        dict: Dictionary containing:
            - sha256 (str): SHA256 hash of raw file
            - md5 (str): MD5 hash of raw file
            - tlsh (str): TLSH hash of processed content (empty if unavailable)
            - ssdeep (str): ssdeep hash of processed content (empty if unavailable)
            - size (int): Size of raw file in bytes
            - file_type (str): MIME type detected
            - processed_size (int): Size of processed content

    Raises:
        FileNotFoundError: If file_path doesn't exist
        PermissionError: If unable to read the file

    Notes:
        - TLSH requires at least 50 bytes of content
        - ssdeep works best with files >= 4096 bytes
        - For PDFs/DOCX, processed content is extracted text
        - For binaries, processed content equals raw content

    Example:
        >>> meta = compute_hashes_and_meta("malware.exe")
        >>> print(f"SHA256: {meta['sha256']}")
        >>> print(f"TLSH: {meta['tlsh']}")
        >>> print(f"File type: {meta['file_type']}")
    """
    with open(file_path, "rb") as f:
        raw_data = f.read()

    # Use FileProcessor to process the file
    processor = FileProcessor(raw_data, os.path.basename(file_path))
    file_type = processor.get_file_type()

    # Process the file (extract text for PDFs/DOCX, or use raw for binaries)
    success, processed_content = processor.process()

    if not success:
        print(f"[WARN] Failed to process {file_path}: {processed_content}")
        # Fall back to raw data if processing fails
        processed_content = raw_data

    # Calculate traditional hashes on RAW data
    sha256 = hashlib.sha256(raw_data).hexdigest()
    md5 = hashlib.md5(raw_data).hexdigest()

    # Calculate similarity hashes on PROCESSED content
    # TLSH
    if tlsh is not None and len(processed_content) >= 50:
        try:
            tlsh_hash = tlsh.hash(processed_content)
        except Exception as e:
            print(f"[WARN] TLSH calculation failed for {file_path}: {e}")
            tlsh_hash = ""
    else:
        tlsh_hash = ""

    # ssdeep
    if ssdeep is not None and len(processed_content) >= 4096:
        try:
            ssdeep_hash = ssdeep.hash(processed_content)
        except Exception as e:
            print(f"[WARN] ssdeep calculation failed for {file_path}: {e}")
            ssdeep_hash = ""
    else:
        ssdeep_hash = ""

    size = len(raw_data)

    return {
        "sha256": sha256,
        "md5": md5,
        "tlsh": tlsh_hash,
        "ssdeep": ssdeep_hash,
        "size": size,
        "file_type": file_type,
        "processed_size": len(processed_content),
    }


# -----------------------------
# Update DB with a file
# -----------------------------
def update_db_with_file(file_path: str, db: dict) -> None:
    """
    Add a file to the database or update if it already exists.

    This function implements smart database updates:
    1. Computes all hashes for the file
    2. Checks if SHA256 already exists in database
    3. If exists: Only updates the filename list and last_upload_date
    4. If new: Creates a complete new entry with all metadata

    This approach prevents duplicate entries while allowing multiple filenames
    to be associated with the same file (useful for tracking file distribution).

    Args:
        file_path (str): Path to the file to add/update
        db (dict): Database dictionary to modify (modified in-place)

    Returns:
        None (modifies db in-place)

    Side Effects:
        - Modifies the db dictionary
        - Prints progress information to stdout

    Behavior:
        - Skips non-file paths with warning
        - Prints detailed info for new entries (hashes, size, type)
        - Updates existing entries silently (only logs filename addition)

    Example:
        >>> db = load_db()
        >>> update_db_with_file("malware.exe", db)
        [INFO] Creating new entry: abc123... (malware.exe)
               Type: application/x-dosexec
               Size: 12345 bytes (processed: 12345 bytes)
               TLSH: T1ABC123...
               ssdeep: 192:ABC...
        >>> save_db(db)
    """
    if not os.path.isfile(file_path):
        print(f"[WARN] Skipping (not a file): {file_path}")
        return

    print(f"[INFO] Processing: {file_path}")

    try:
        meta = compute_hashes_and_meta(file_path)
    except Exception as e:
        print(f"[ERROR] Failed to process {file_path}: {e}")
        return

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
            print(
                f"[INFO] Updated existing entry: {sha256[:16]}... (added name: {base_name})"
            )

        existing_entry["last_upload_date"] = now_iso
        return

    # New entry
    print(f"[INFO] Creating new entry: {sha256[:16]}... ({base_name})")
    print(f"       Type: {meta['file_type']}")
    print(
        f"       Size: {meta['size']} bytes (processed: {meta['processed_size']} bytes)"
    )
    print(f"       TLSH: {meta['tlsh'][:32] if meta['tlsh'] else 'N/A'}...")
    print(f"       ssdeep: {meta['ssdeep'][:32] if meta['ssdeep'] else 'N/A'}...")

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
    Build an in-memory similarity index for fast hash lookups.

    Creates a reverse index mapping similarity hashes to SHA256 values,
    enabling fast lookups during similarity searches. This avoids having
    to iterate through the entire database for each comparison.

    Args:
        db (dict): Complete file database

    Returns:
        dict: Similarity index with structure:
            {
                "tlsh": {
                    "tlsh_hash_1": "sha256_1",
                    "tlsh_hash_2": "sha256_2",
                    ...
                },
                "ssdeep": {
                    "ssdeep_hash_1": "sha256_1",
                    "ssdeep_hash_2": "sha256_2",
                    ...
                }
            }

    Notes:
        - If multiple files share the same similarity hash, only the last
          one is kept in the index (hash collision)
        - Empty hashes are skipped
        - Files without similarity hashes won't appear in the index

    Performance:
        - Time: O(n) where n is number of files in database
        - Space: O(h) where h is number of unique hashes

    Example:
        >>> db = load_db()
        >>> index = build_similarity_index(db)
        >>> print(f"TLSH index size: {len(index['tlsh'])}")
        >>> print(f"ssdeep index size: {len(index['ssdeep'])}")
        TLSH index size: 145
        ssdeep index size: 120
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
    Load database and return only the similarity index.

    Convenience function that combines loading the database from disk
    and building the similarity index in one call.

    Args:
        path (str): Path to the database file (default: db/file_db.json)

    Returns:
        dict: Similarity index (see build_similarity_index for structure)

    Example:
        >>> index = load_similarity_index()
        >>> # Ready to use for similarity searches
    """
    db = load_db(path)
    return build_similarity_index(db)


# -----------------------------
# Expand arguments (files or directories)
# -----------------------------
def expand_arguments(args):
    """
    Expand file paths and directories into a flat list of files.

    Takes a list of paths (files or directories) and expands directories
    into their contained files. Non-recursive - only processes files directly
    in the specified directories.

    Args:
        args (list): List of file paths and/or directory paths

    Returns:
        list: Flat list of file paths (str)

    Behavior:
        - Files are added directly to the result
        - Directories are expanded to include all their files (non-recursive)
        - Invalid paths generate warnings but don't stop processing
        - Subdirectories within directories are skipped

    Example:
        >>> paths = ["file1.exe", "/path/to/directory", "file2.pdf"]
        >>> files = expand_arguments(paths)
        >>> print(files)
        ['file1.exe', '/path/to/directory/a.exe',
         '/path/to/directory/b.exe', 'file2.pdf']
    """
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
    """
    Main CLI entry point for batch database generation.

    Processes command-line arguments, expands directories, computes hashes
    for all files, updates the database, and builds the similarity index.

    Args:
        argv (list | None): Command-line arguments (default: sys.argv[1:])
                           If None, uses sys.argv

    Returns:
        None (exits with status code)

    Exit Codes:
        0: Success
        1: Error (no arguments, no valid files, etc.)

    Workflow:
        1. Parse command-line arguments
        2. Expand directories to file list
        3. Load existing database
        4. Process each file (compute hashes, update database)
        5. Save updated database to disk
        6. Build and display similarity index statistics

    Output:
        Prints progress information to stdout:
        - Files being processed
        - New entries created
        - Existing entries updated
        - Final statistics (total entries, processed files, errors)
        - Similarity index statistics

    Example Usage:
        # Process all files in a directory
        $ python3 db/json_parser.py /path/to/malware/samples/

        # Process specific files
        $ python3 db/json_parser.py file1.exe file2.pdf file3.docx

        # Mix files and directories
        $ python3 db/json_parser.py file1.exe /path/to/dir/ file2.pdf

    Example Output:
        [INFO] Loaded database with 100 existing entries
        [INFO] Processing: /path/to/file1.exe
        [INFO] Creating new entry: abc123... (file1.exe)
               Type: application/x-dosexec
               Size: 12345 bytes (processed: 12345 bytes)
               TLSH: T1ABC...
               ssdeep: 192:...

        [INFO] Database update complete:
               Total entries: 101
               Files processed: 1
               Errors: 0
               Saved to: db/file_db.json

        [INFO] Similarity index built:
               TLSH hashes: 95
               ssdeep hashes: 85
    """
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
    print(f"[INFO] Loaded database with {len(db)} existing entries")

    processed_count = 0
    error_count = 0

    for file_path in file_list:
        try:
            update_db_with_file(file_path, db)
            processed_count += 1
        except Exception as e:
            print(f"[ERROR] Failed to process {file_path}: {e}")
            error_count += 1

    save_db(db, DB_PATH)
    print(f"\n[INFO] Database update complete:")
    print(f"       Total entries: {len(db)}")
    print(f"       Files processed: {processed_count}")
    print(f"       Errors: {error_count}")
    print(f"       Saved to: {DB_PATH}")

    sim_index = build_similarity_index(db)
    print(f"\n[INFO] Similarity index built:")
    print(f"       TLSH hashes: {len(sim_index['tlsh'])}")
    print(f"       ssdeep hashes: {len(sim_index['ssdeep'])}")


if __name__ == "__main__":
    main()
