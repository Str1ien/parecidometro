from flask import Flask, render_template, request, jsonify
import tlsh
import json
from managers.file_processor import FileProcessor

N_TOP_MATCHES = 10

app = Flask(__name__)

# Cargar base de datos
with open('database.json', 'r') as f:
    database = json.load(f)

def calculate_tlsh(file_content):
    """
    Calcula TLSH sobre contenido procesado
    - Para ejecutables: sobre código desensamblado de sección .text
    - Para PDF: sobre texto extraído de todas las páginas  
    - Para DOCX: sobre texto extraído de todos los párrafos
    
    Return:
        tuple: (success: bool, tlsh_hash: str | error_message: str)
    """
    content_size = len(file_content)
    
    # Validar tamaño mínimo
    if content_size < 50:
        return False, f'Content too small for TLSH (min 50 bytes, got {content_size})'
    
    try:
        uploaded_hash = tlsh.hash(file_content)
        if uploaded_hash is None or uploaded_hash == "":
            return False, "TLSH returned empty hash (insufficient randomness)"
        
        return True, uploaded_hash
        
    except Exception as e:
        return False, f'Cannot compute TLSH: {str(e)}'


@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/visualize/<file_sha256>")
def visualize(file_sha256):
    return render_template("visualize.html", file_sha256=file_sha256)


@app.route("/api/file/<file_sha256>")
def api_file(file_sha256):
    pass

@app.route('/api/compare', methods=['POST'])
def compare_binary():
    """Endpoint principal para comparar archivos"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    file_data = file.read()
    
    # Procesar archivo según tipo
    processor = FileProcessor(file_data, file.filename)
    file_type = processor.get_file_type()
    
    success, file_content = processor.process()
    
    if not success:
        # file_content contiene el mensaje de error
        return jsonify({
            'error': 'File processing failed',
            'filename': file.filename,
            'detected_type': file_type,
            'details': file_content
        }), 400
    
    # Calcular TLSH
    tlsh_success, tlsh_result = calculate_tlsh(file_content)
    
    if not tlsh_success:
        # tlsh_result contiene el mensaje de error
        return jsonify({
            'error': 'TLSH calculation failed',
            'filename': file.filename,
            'file_type': file_type,
            'details': tlsh_result
        }), 400
    
    # tlsh_result contiene el hash
    uploaded_hash = tlsh_result
    content_size = len(file_content)
    
    # Buscar el más similar en la BD
    best_match = None
    min_distance = float('inf')
    all_matches = []
    
    for entry in database:
        try:
            distance = tlsh.diff(uploaded_hash, entry['tlsh'])
            all_matches.append({
                'id': entry['id'],
                'filename': entry['filename'],
                'distance': distance
            })
            if distance < min_distance:
                min_distance = distance
                best_match = entry
        except Exception as e:
            print(f"Error comparing with {entry.get('id', 'unknown')}: {e}")
            continue
    
    # Ordenar top matches
    all_matches.sort(key=lambda x: x['distance'])
    top_matches = all_matches[:N_TOP_MATCHES]
    
    return jsonify({
        'uploaded_file': {
            'filename': file.filename,
            'tlsh': uploaded_hash,
            'file_type': file_type,
            'content_size_bytes': content_size,
            # TODO: Meter metadata (exiftools?)
        },
        'best_match': best_match,
        'similarity_score': min_distance,
        f'top_{N_TOP_MATCHES}_matches': top_matches
    })


@app.route('/api/health', methods=['GET'])
def health():
    """Healthcheck"""
    return jsonify({
        'status': 'ok',
        'database_size': len(database),
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
