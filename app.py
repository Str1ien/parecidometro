"""
═══════════════════════════════════════════════════════════════════════════
                            PARECIDÓMETRO
                    Similarity Detection System
                        CyberArena Hackathon 2025
═══════════════════════════════════════════════════════════════════════════

Description:
    Web application for comparing files using fuzzy hashing algorithms
    (TLSH and ssdeep) to detect binaries, documents, and malware variants.

Supported file types:
    • Executables (PE/ELF)
    • PDF documents
    • Microsoft Word (DOCX)
    • Generic files

Authors:
    - Alain "Str1ien" Villagrasa
    - Daniel "Kifixo" Huici
    - Razvan "Razvi" Raducu

License: MIT License
Date: December 2025
"""

from flask import Flask, render_template, request, jsonify
import logging
from managers.file_processor import FileProcessor
from managers.hash_manager import HashManager
from db.json_parser import build_similarity_index, load_db, DB_PATH
import hashlib
from datetime import datetime
from db.json_parser import save_db


# Configuration
TOP_MATCHES = 10
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Logging config
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

database = {}
similarity_index = {}


def initialize_app():
    """
    Initialize the database and similarity index.

    Loads the JSON database from disk and builds an in-memory similarity
    index for fast TLSH and ssdeep lookups.

    Global Variables Modified:
        database (dict): Complete file database {sha256: {metadata}}
        similarity_index (dict): Index for fast similarity lookups
                                {tlsh: {hash: sha256}, ssdeep: {hash: sha256}}
    """
    global database, similarity_index

    logger.info(f"Loading database from {DB_PATH}...")
    database = load_db(DB_PATH)
    logger.info(f"Database loaded: {len(database)} entries")

    logger.info("Building similarity index...")
    similarity_index = build_similarity_index(database)
    logger.info(
        f"Index built: {len(similarity_index['tlsh'])} TLSH, {len(similarity_index['ssdeep'])} ssdeep"
    )


initialize_app()


@app.route("/")
def landing():
    """
    Render the landing page.

    Returns:
        str: Rendered HTML template for the file upload page
    """
    return render_template("landing.html")


@app.route("/visualize/<file_id>")
def visualize(file_id):
    """
    Render the visualization page for a specific file.

    Args:
        file_id (str): SHA256 hash of the file to visualize, or "new" for
                      newly uploaded files

    Returns:
        str: Rendered HTML template with file visualization
    """
    return render_template("visualize.html", file_id=file_id)


@app.route("/api/file/<file_sha256>")
def api_file(file_sha256):
    """
    Get file information by SHA256 hash and calculate similarities.

    This endpoint retrieves a file from the database and performs on-the-fly
    similarity calculations against all other files in the database.

    Args:
        file_sha256 (str): SHA256 hash of the file to retrieve

    Returns:
        Response: JSON response containing:
            - sha256 (str): File's SHA256 hash
            - name (list): List of filenames associated with this hash
            - size (int): File size in bytes
            - file_type (str): MIME type
            - hashes (dict): All calculated hashes
            - similar (list): Array of similar files with scores

        Status Codes:
            200: Success
            404: File not found in database

    Example Response:
        {
            "sha256": "abc123...",
            "name": ["malware.exe"],
            "size": 12345,
            "file_type": "application/x-dosexec",
            "hashes": {
                "sha256": "abc123...",
                "md5": "def456...",
                "tlsh": "T1...",
                "ssdeep": "192:..."
            },
            "similar": [
                {
                    "sha256": "xyz789...",
                    "name": ["variant.exe"],
                    "family": "Trojan",
                    "file_type": "application/x-dosexec",
                    "tags": ["malware"],
                    "tlsh_score": 95.0,
                    "ssdeep_score": 85
                }
            ]
        }
    """
    file_entry = database.get(file_sha256)

    if not file_entry:
        logger.warning(f"File not found: {file_sha256}")
        return jsonify({"error": "File not found"}), 404

    logger.info(f"File info requested: {file_sha256}")

    # Get hashes from database entry
    hashes = file_entry.get("hashes", {})
    tlsh_hash = hashes.get("tlsh")
    ssdeep_hash = hashes.get("ssdeep")

    # Initialize hash manager for comparison
    hash_manager = HashManager(database, similarity_index)

    # Build similar array by comparing against database
    similar = []

    # Find TLSH matches if hash exists
    if tlsh_hash:
        tlsh_matches = hash_manager.find_matches_tlsh(tlsh_hash, top_n=TOP_MATCHES)
        for match in tlsh_matches["top_matches"]:
            # Don't skip self-match anymore - include it!
            similar_entry = {
                "sha256": match["sha256"],
                "name": match["name"],
                "family": match.get("family", "Unknown"),
                "file_type": match.get("file_type", "Unknown"),
                "tags": match.get("tags", []),
                "tlsh_score": max(0, 100 - match["distance"]),
                "ssdeep_score": 0,
            }
            similar.append(similar_entry)

    # Find ssdeep matches if hash exists and add/update scores
    if ssdeep_hash:
        ssdeep_matches = hash_manager.find_matches_ssdeep(
            ssdeep_hash, top_n=TOP_MATCHES
        )

        # Create a map for efficient lookup
        similar_map = {s["sha256"]: s for s in similar}

        for match in ssdeep_matches["top_matches"]:
            # Don't skip self-match anymore - include it!
            if match["sha256"] in similar_map:
                # Update existing entry with ssdeep score
                similar_map[match["sha256"]]["ssdeep_score"] = match["similarity"]
            else:
                # Add new entry
                similar_entry = {
                    "sha256": match["sha256"],
                    "name": match["name"],
                    "family": match.get("family", "Unknown"),
                    "file_type": match.get("file_type", "Unknown"),
                    "tags": match.get("tags", []),
                    "tlsh_score": 0,
                    "ssdeep_score": match["similarity"],
                }
                similar.append(similar_entry)
                similar_map[match["sha256"]] = similar_entry

    # Add similar array to response
    response = {"sha256": file_sha256, **file_entry, "similar": similar}

    logger.info(f"Returning file info with {len(similar)} similar files")
    return jsonify(response)


@app.route("/api/reload", methods=["POST"])
def reload_database():
    """
    Reload the database without restarting the server.

    This endpoint allows administrators to reload the file database and
    rebuild the similarity index after manual changes to the database file.

    Returns:
        Response: JSON response containing:
            - status (str): "success" or "error"
            - message (str): Status message
            - database_size (int): Number of files in database
            - tlsh_index_size (int): Number of TLSH hashes indexed
            - ssdeep_index_size (int): Number of ssdeep hashes indexed

        Status Codes:
            200: Success
            500: Error reloading database

    Example Response:
        {
            "status": "success",
            "message": "Database reloaded",
            "database_size": 150,
            "tlsh_index_size": 145,
            "ssdeep_index_size": 120
        }
    """
    try:
        logger.info("Database reload requested")
        initialize_app()
        return jsonify(
            {
                "status": "success",
                "message": "Database reloaded",
                "database_size": len(database),
                "tlsh_index_size": len(similarity_index.get("tlsh", {})),
                "ssdeep_index_size": len(similarity_index.get("ssdeep", {})),
            }
        )
    except Exception as e:
        logger.error(f"Error reloading database: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


def save_file_to_database(sha256, filename, file_size, file_type, hashes):
    """
    Save a new file to the database.

    Creates a new database entry for the file and persists it to disk.
    Automatically rebuilds the similarity index to include the new file.

    Args:
        sha256 (str): SHA256 hash of the file
        filename (str): Original filename
        file_size (int): File size in bytes
        file_type (str): MIME type of the file
        hashes (dict): Dictionary containing all calculated hashes:
            - sha256 (str): SHA256 hash
            - md5 (str): MD5 hash
            - tlsh (str): TLSH similarity hash
            - ssdeep (str): ssdeep similarity hash

    Returns:
        bool: True if saved successfully, False if file already exists

    Global Variables Modified:
        database (dict): Updated with new file entry
        similarity_index (dict): Rebuilt to include new file

    Side Effects:
        - Writes updated database to disk (file_db.json)
        - Rebuilds similarity index in memory
        - Logs operation status

    Example:
        >>> hashes = {
        ...     "sha256": "abc123...",
        ...     "md5": "def456...",
        ...     "tlsh": "T1...",
        ...     "ssdeep": "192:..."
        ... }
        >>> save_file_to_database("abc123...", "malware.exe", 12345,
        ...                       "application/x-dosexec", hashes)
        True
    """
    global database, similarity_index

    # Check if already exists
    if sha256 in database:
        logger.info(f"File already in database: {sha256}")
        return False

    # Create new entry
    now_iso = datetime.utcnow().isoformat() + "Z"

    database[sha256] = {
        "name": [filename],
        "size": file_size,
        "file_type": file_type,
        "first_upload_date": now_iso,
        "last_upload_date": now_iso,
        "desc": "",
        "hashes": {
            "sha256": hashes.get("sha256", sha256),
            "md5": hashes.get("md5", ""),
            "tlsh": hashes.get("tlsh", ""),
            "ssdeep": hashes.get("ssdeep", ""),
        },
    }

    # Save to disk
    try:
        save_db(database, DB_PATH)
        logger.info(f"File saved to database: {sha256} ({filename})")

        # Rebuild similarity index to include new file
        similarity_index = build_similarity_index(database)
        logger.info(
            f"Similarity index rebuilt: {len(similarity_index['tlsh'])} TLSH, {len(similarity_index['ssdeep'])} ssdeep"
        )

        return True
    except Exception as e:
        logger.error(f"Error saving file to database: {e}")
        # Rollback - remove from in-memory database
        del database[sha256]
        return False


@app.route("/api/compare", methods=["POST"])
def compare_binary():
    """
    Main endpoint for comparing files using TLSH and ssdeep.

    This endpoint processes an uploaded file, calculates all hashes (traditional
    and similarity), compares it against the database, and optionally saves it.

    Form Parameters:
        file (FileStorage): The uploaded file (required)
        save_to_db (str): "true" to save the file to database, "false" otherwise
                         (optional, default: "false")

    Returns:
        Response: JSON response containing:
            - uploaded_file (dict): Information about the uploaded file
                - filename (str): Original filename
                - file_type (str): Detected MIME type
                - content_size_bytes (int): Processed content size
                - sha256 (str): SHA256 hash
                - exists_in_database (bool): Whether file exists in DB
                - saved_to_database (bool): Whether file was saved to DB
                - hashes (dict): All calculated hashes
            - tlsh (dict): TLSH comparison results
                - best_match (dict): Best matching file
                - similarity_score (int): Distance to best match
                - top_N_matches (list): Top N similar files
                - total_comparisons (int): Number of files compared
            - ssdeep (dict): ssdeep comparison results (same structure as tlsh)

        Status Codes:
            200: Success
            400: Invalid request (no file, empty file, processing failed)
            413: File too large

    Processing Steps:
        1. Validates file upload
        2. Calculates SHA256 and MD5 on raw data
        3. Processes file content (extracts text from PDFs/DOCX if applicable)
        4. Calculates TLSH and ssdeep on processed content
        5. Finds similar files in database
        6. Optionally saves new file to database

    Example Request:
        POST /api/compare
        Content-Type: multipart/form-data

        file=@malware.exe
        save_to_db=true

    Example Response:
        {
            "uploaded_file": {
                "filename": "malware.exe",
                "file_type": "application/x-dosexec",
                "content_size_bytes": 12345,
                "sha256": "abc123...",
                "exists_in_database": false,
                "saved_to_database": true,
                "hashes": {
                    "sha256": "abc123...",
                    "md5": "def456...",
                    "tlsh": "T1...",
                    "ssdeep": "192:..."
                }
            },
            "tlsh": {
                "best_match": {
                    "sha256": "xyz789...",
                    "name": ["variant.exe"],
                    "distance": 15
                },
                "similarity_score": 15,
                "top_10_matches": [...],
                "total_comparisons": 150
            },
            "ssdeep": {
                "best_match": null,
                "similarity_score": 0,
                "top_10_matches": [],
                "total_comparisons": 120
            }
        }
    """

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Check if we should save the file to database (optional parameter)
    save_to_db = request.form.get("save_to_db", "false").lower() == "true"

    file_data = file.read()
    file_size = len(file_data)

    logger.info(
        f"File upload: {file.filename} ({file_size} bytes, save_to_db={save_to_db})"
    )

    # Validar tamaño del archivo
    if file_size > MAX_FILE_SIZE:
        logger.warning(f"File too large: {file.filename} ({file_size} bytes)")
        return (
            jsonify(
                {
                    "error": "File too large",
                    "filename": file.filename,
                    "file_size_bytes": file_size,
                    "max_size_bytes": MAX_FILE_SIZE,
                    "max_size_mb": MAX_FILE_SIZE / (1024 * 1024),
                }
            ),
            413,
        )

    # 1. Calculate traditional hashes on RAW data
    sha256_hash = hashlib.sha256(file_data).hexdigest()
    md5_hash = hashlib.md5(file_data).hexdigest()

    logger.info(f"Hashes calculated - SHA256: {sha256_hash}, MD5: {md5_hash}")

    # Check if file already exists in database
    existing_file = database.get(sha256_hash)

    # 2. Procesar archivo según tipo
    processor = FileProcessor(file_data, file.filename)
    file_type = processor.get_file_type()
    logger.info(f"File type detected: {file_type}")

    success, file_content = processor.process()

    if not success:
        logger.error(f"File processing failed: {file.filename} - {file_content}")
        return (
            jsonify(
                {
                    "error": "File processing failed",
                    "filename": file.filename,
                    "detected_type": file_type,
                    "details": file_content,
                }
            ),
            400,
        )

    # 3. Calcular similarity hashes (TLSH + ssdeep) on PROCESSED content
    hash_manager = HashManager(database, similarity_index)
    success, result = hash_manager.compare_file(
        file_content, top_n=TOP_MATCHES, use_ssdeep=True
    )

    if not success:
        logger.error(f"Hash calculation failed: {file.filename} - {result}")
        return (
            jsonify(
                {
                    "error": "Hash calculation failed",
                    "filename": file.filename,
                    "file_type": file_type,
                    "details": result,
                }
            ),
            400,
        )

    logger.info(
        f"Similarity hashes calculated - TLSH: {result['tlsh'].get('hash', 'N/A')[:16]}..., ssdeep: {result['ssdeep'].get('hash', 'N/A')[:16]}..."
    )

    # Prepare all hashes
    all_hashes = {
        "sha256": sha256_hash,
        "md5": md5_hash,
        "tlsh": result["tlsh"].get("hash", ""),
        "ssdeep": result["ssdeep"].get("hash", ""),
    }

    # 4. Save to database if requested and not already exists
    saved_to_db = False
    if save_to_db and not existing_file:
        saved_to_db = save_file_to_database(
            sha256_hash, file.filename, file_size, file_type, all_hashes
        )

    # 5. Build response
    response = {
        "uploaded_file": {
            "filename": file.filename,
            "file_type": file_type,
            "content_size_bytes": result["content_size"],
            "sha256": sha256_hash,
            "exists_in_database": existing_file is not None or saved_to_db,
            "saved_to_database": saved_to_db,
            "hashes": all_hashes,
        },
        "tlsh": {
            "best_match": None,
            "similarity_score": result["tlsh"]["matches"]["min_distance"],
            f"top_{TOP_MATCHES}_matches": result["tlsh"]["matches"]["top_matches"],
            "total_comparisons": result["tlsh"]["matches"]["all_matches_count"],
        },
    }

    # Add TLSH best_match if exists
    if result["tlsh"]["matches"]["best_match"]:
        best_sha256 = result["tlsh"]["matches"]["best_match_sha256"]
        logger.info(
            f"TLSH best match found: {best_sha256} (distance: {result['tlsh']['matches']['min_distance']})"
        )
        response["tlsh"]["best_match"] = {
            "sha256": best_sha256,
            **result["tlsh"]["matches"]["best_match"],
        }

    # Add ssdeep results
    if "matches" in result["ssdeep"]:
        response["ssdeep"] = {
            "best_match": None,
            "similarity_score": result["ssdeep"]["matches"]["max_similarity"],
            f"top_{TOP_MATCHES}_matches": result["ssdeep"]["matches"]["top_matches"],
            "total_comparisons": result["ssdeep"]["matches"]["all_matches_count"],
        }

        if result["ssdeep"]["matches"]["best_match"]:
            best_sha256_ssdeep = result["ssdeep"]["matches"]["best_match_sha256"]
            logger.info(
                f"ssdeep best match found: {best_sha256_ssdeep} (similarity: {result['ssdeep']['matches']['max_similarity']}%)"
            )
            response["ssdeep"]["best_match"] = {
                "sha256": best_sha256_ssdeep,
                **result["ssdeep"]["matches"]["best_match"],
            }
    elif "error" in result["ssdeep"]:
        logger.warning(f"ssdeep calculation failed: {result['ssdeep']['error']}")
        response["ssdeep"] = {"error": result["ssdeep"]["error"]}

    return jsonify(response)


@app.route("/api/health", methods=["GET"])
def health():
    """
    Health check endpoint for monitoring.

    Returns system status and statistics about the database and indices.
    Useful for monitoring tools and load balancers.

    Returns:
        Response: JSON response containing:
            - status (str): "ok" if system is healthy
            - database_size (int): Number of files in database
            - tlsh_index_size (int): Number of TLSH hashes indexed
            - ssdeep_index_size (int): Number of ssdeep hashes indexed
            - version (str): Application version

        Status Codes:
            200: Always returns 200 if server is running

    Example Response:
        {
            "status": "ok",
            "database_size": 150,
            "tlsh_index_size": 145,
            "ssdeep_index_size": 120,
            "version": "1.0.0"
        }
    """
    return jsonify(
        {
            "status": "ok",
            "database_size": len(database),
            "tlsh_index_size": len(similarity_index.get("tlsh", {})),
            "ssdeep_index_size": len(similarity_index.get("ssdeep", {})),
            "version": "1.0.0",
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
