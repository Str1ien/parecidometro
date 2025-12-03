from flask import Flask, render_template, request, jsonify
import json
import os
import logging
from managers.file_processor import FileProcessor
from managers.hash_manager import HashManager


# Configuración
TOP_MATCHES = 10
DB_PATH = "file_db.json"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Variables globales: SOLO datos
# Ambas son necesarias por diferentes motivos:
# - database: acceso directo por SHA256 para metadata completa
# - similarity_index: búsqueda O(1) por hash durante comparación
database = {}
similarity_index = {}


def load_db(path: str = DB_PATH) -> dict:
    """Load the JSON database from disk, or return an empty dict if it doesn't exist."""
    if not os.path.exists(path):
        logger.warning(f"Database file {path} not found, starting with empty DB.")
        return {}
    
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_similarity_index(db: dict) -> dict:
    """
    Build similarity index from database.
    Maps hash -> sha256 for O(1) lookup during comparison.
    
    Why we need BOTH database and similarity_index:
    - database: Direct access by SHA256 → get full metadata
    - similarity_index: Fast lookup by hash → find which SHA256 to query
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


def initialize_app():
    """Initialize/reload database and similarity index"""
    global database, similarity_index
    
    logger.info(f"Loading database from {DB_PATH}...")
    database = load_db(DB_PATH)
    logger.info(f"Database loaded: {len(database)} entries")
    
    logger.info("Building similarity index...")
    similarity_index = build_similarity_index(database)
    logger.info(f"Index built: {len(similarity_index['tlsh'])} TLSH, {len(similarity_index['ssdeep'])} ssdeep")


# Cargar BD al inicio
initialize_app()


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/visualize/<file_sha256>")
def visualize(file_sha256):
    return render_template("visualize.html", file_sha256=file_sha256)


@app.route("/api/file/<file_sha256>")
def api_file(file_sha256):
    """
    Obtener información de un archivo por su SHA256
    
    Este endpoint necesita 'database' (no puede usar solo similarity_index)
    porque necesita acceso directo por SHA256
    """
    file_entry = database.get(file_sha256)
    
    if not file_entry:
        logger.warning(f"File not found: {file_sha256}")
        return jsonify({'error': 'File not found'}), 404
    
    logger.info(f"File info requested: {file_sha256}")
    return jsonify({
        'sha256': file_sha256,
        **file_entry
    })


@app.route('/api/reload', methods=['POST'])
def reload_database():
    """Recarga la base de datos sin reiniciar el servidor"""
    try:
        logger.info("Database reload requested")
        initialize_app()
        return jsonify({
            'status': 'success',
            'message': 'Database reloaded',
            'database_size': len(database),
            'tlsh_index_size': len(similarity_index.get('tlsh', {})),
            'ssdeep_index_size': len(similarity_index.get('ssdeep', {}))
        })
    except Exception as e:
        logger.error(f"Error reloading database: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/compare', methods=['POST'])
def compare_binary():
    """Endpoint principal para comparar archivos usando TLSH y ssdeep"""
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    file_data = file.read()
    file_size = len(file_data)
    
    logger.info(f"File upload: {file.filename} ({file_size} bytes)")
    
    # Validar tamaño del archivo
    if file_size > MAX_FILE_SIZE:
        logger.warning(f"File too large: {file.filename} ({file_size} bytes)")
        return jsonify({
            'error': 'File too large',
            'filename': file.filename,
            'file_size_bytes': file_size,
            'max_size_bytes': MAX_FILE_SIZE,
            'max_size_mb': MAX_FILE_SIZE / (1024 * 1024)
        }), 413
    
    # 1. Procesar archivo según tipo
    processor = FileProcessor(file_data, file.filename)
    file_type = processor.get_file_type()
    logger.info(f"File type detected: {file_type}")
    
    success, file_content = processor.process()
    
    if not success:
        logger.error(f"File processing failed: {file.filename} - {file_content}")
        return jsonify({
            'error': 'File processing failed',
            'filename': file.filename,
            'detected_type': file_type,
            'details': file_content
        }), 400
    
    # 2. Crear HashManager y calcular ambos hashes (TLSH + ssdeep)
    hash_manager = HashManager(database, similarity_index)
    success, result = hash_manager.compare_file(file_content, top_n=TOP_MATCHES, use_ssdeep=True)
    
    if not success:
        logger.error(f"Hash calculation failed: {file.filename} - {result}")
        return jsonify({
            'error': 'Hash calculation failed',
            'filename': file.filename,
            'file_type': file_type,
            'details': result
        }), 400
    
    logger.info(f"Hashes calculated - TLSH: {result['tlsh'].get('hash')[:16]}..., ssdeep: {result['ssdeep'].get('hash', 'N/A')[:16]}...")
    
    # 3. Construir respuesta
    response = {
        'uploaded_file': {
            'filename': file.filename,
            'file_type': file_type,
            'content_size_bytes': result['content_size'],
            'hashes': {
                'tlsh': result['tlsh'].get('hash'),
                'ssdeep': result['ssdeep'].get('hash')
            }
        },
        'tlsh': {
            'best_match': None,
            'similarity_score': result['tlsh']['matches']['min_distance'],
            'interpretation': hash_manager.interpret_tlsh_distance(
                result['tlsh']['matches']['min_distance']
            ),
            f'top_{TOP_MATCHES}_matches': result['tlsh']['matches']['top_matches'],
            'total_comparisons': result['tlsh']['matches']['all_matches_count']
        }
    }
    
    # Añadir best_match TLSH si existe
    if result['tlsh']['matches']['best_match']:
        best_sha256 = result['tlsh']['matches']['best_match_sha256']
        logger.info(f"TLSH best match found: {best_sha256} (distance: {result['tlsh']['matches']['min_distance']})")
        response['tlsh']['best_match'] = {
            'sha256': best_sha256,
            **result['tlsh']['matches']['best_match']
        }
    
    # Añadir resultados ssdeep
    if 'matches' in result['ssdeep']:
        response['ssdeep'] = {
            'best_match': None,
            'similarity_score': result['ssdeep']['matches']['max_similarity'],
            'interpretation': hash_manager.interpret_ssdeep_similarity(
                result['ssdeep']['matches']['max_similarity']
            ),
            f'top_{TOP_MATCHES}_matches': result['ssdeep']['matches']['top_matches'],
            'total_comparisons': result['ssdeep']['matches']['all_matches_count']
        }
        
        if result['ssdeep']['matches']['best_match']:
            best_sha256_ssdeep = result['ssdeep']['matches']['best_match_sha256']
            logger.info(f"ssdeep best match found: {best_sha256_ssdeep} (similarity: {result['ssdeep']['matches']['max_similarity']}%)")
            response['ssdeep']['best_match'] = {
                'sha256': best_sha256_ssdeep,
                **result['ssdeep']['matches']['best_match']
            }
    elif 'error' in result['ssdeep']:
        logger.warning(f"ssdeep calculation failed: {result['ssdeep']['error']}")
        response['ssdeep'] = {
            'error': result['ssdeep']['error']
        }
    
    return jsonify(response)


@app.route('/api/health', methods=['GET'])
def health():
    """Healthcheck"""
    return jsonify({
        'status': 'ok',
        'database_size': len(database),
        'tlsh_index_size': len(similarity_index.get('tlsh', {})),
        'ssdeep_index_size': len(similarity_index.get('ssdeep', {})),
        'version': '1.0.0'
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
