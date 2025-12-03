"""
═══════════════════════════════════════════════════════════════════════════
                            PARECIDÓMETRO
                    Sistema de Detección por Similitud
                        Hackathon CyberArena 2025
═══════════════════════════════════════════════════════════════════════════

Descripción:
    Aplicación web para comparar archivos mediante algoritmos de hashing
    difuso (TLSH y ssdeep) para detectar binarios, documentos y variantes
    de malware similares.

Tipos de archivo soportados:
    • Ejecutables (PE/ELF)
    • Documentos PDF
    • Microsoft Word (DOCX)
    • Archivos genéricos

Autores:
    - Alain "Str1ien" Villagrasa
    - Daniel "Kifixo" Huici
    - Razvan "Razvi" Raducu

Licencia: MIT License
Fecha: Diciembre 2025
"""

from flask import Flask, render_template, request, jsonify
import logging
from managers.file_processor import FileProcessor
from managers.hash_manager import HashManager
from db.json_parser import build_similarity_index, load_db, DB_PATH
import hashlib


# Configuración
TOP_MATCHES = 10
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Configurar logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

database = {}
similarity_index = {}


def initialize_app():
    """Inicialización de la base de datos e índice de similitud"""
    global database, similarity_index

    logger.info(f"Loading database from {DB_PATH}...")
    database = load_db(DB_PATH)
    logger.info(f"Database loaded: {len(database)} entries")

    logger.info("Building similarity index...")
    similarity_index = build_similarity_index(database)
    logger.info(
        f"Index built: {len(similarity_index['tlsh'])} TLSH, {len(similarity_index['ssdeep'])} ssdeep"
    )


# Cargar BD al inicio
initialize_app()


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/visualize/<file_id>")
def visualize(file_id):
    return render_template("visualize.html", file_id=file_id)


@app.route("/api/file/<file_sha256>")
def api_file(file_sha256):
    """
    Obtener información de un archivo por su SHA256 y calcular similitudes
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
    """Recarga la base de datos sin reiniciar el servidor"""
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


@app.route("/api/compare", methods=["POST"])
def compare_binary():
    """Endpoint principal para comparar archivos usando TLSH y ssdeep"""

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    file_data = file.read()
    file_size = len(file_data)

    logger.info(f"File upload: {file.filename} ({file_size} bytes)")

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

    # 4. Construir respuesta
    response = {
        "uploaded_file": {
            "filename": file.filename,
            "file_type": file_type,
            "content_size_bytes": result["content_size"],
            "sha256": sha256_hash,
            "exists_in_database": existing_file is not None,
            "hashes": {
                "sha256": sha256_hash,
                "md5": md5_hash,
                "tlsh": result["tlsh"].get("hash"),
                "ssdeep": result["ssdeep"].get("hash"),
            },
        },
        "tlsh": {
            "best_match": None,
            "similarity_score": result["tlsh"]["matches"]["min_distance"],
            f"top_{TOP_MATCHES}_matches": result["tlsh"]["matches"]["top_matches"],
            "total_comparisons": result["tlsh"]["matches"]["all_matches_count"],
        },
    }

    # Añadir best_match TLSH si existe
    if result["tlsh"]["matches"]["best_match"]:
        best_sha256 = result["tlsh"]["matches"]["best_match_sha256"]
        logger.info(
            f"TLSH best match found: {best_sha256} (distance: {result['tlsh']['matches']['min_distance']})"
        )
        response["tlsh"]["best_match"] = {
            "sha256": best_sha256,
            **result["tlsh"]["matches"]["best_match"],
        }

    # Añadir resultados ssdeep
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
    """Healthcheck"""
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
