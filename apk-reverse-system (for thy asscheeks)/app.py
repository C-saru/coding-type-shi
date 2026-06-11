import os
import sys
import uuid
import threading
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename

# Asegurar que el directorio raíz está en el path
sys.path.insert(0, str(Path(__file__).parent))

from modules.main import APKReverseSystem
from modules.ingester import APKIngester

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Configurar directorios de trabajo
BASE_DIR = Path(__file__).parent
UPLOAD_FOLDER = BASE_DIR / "input"
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)

# Inicializar el motor del framework
system = APKReverseSystem(base_dir=str(BASE_DIR))

# Estructura en memoria para rastrear tareas en segundo plano
active_tasks = {}

def run_analysis_in_background(task_id: str, apk_path: str, package_name: str, device_connected: bool):
    active_tasks[task_id]['status'] = 'running'
    active_tasks[task_id]['stage'] = 'ingest'
    
    try:
        # Si no se pasó ruta de APK, se extrae dinámicamente desde el dispositivo conectado
        if not apk_path and package_name:
            active_tasks[task_id]['stage'] = 'extracting'
            # Simular extracción del pipeline usando adb
            work_dir = BASE_DIR / "output" / "extracted_apks" / package_name
            work_dir.mkdir(parents=True, exist_ok=True)
            
            # Invocar extracción manual
            import subprocess
            result = subprocess.run(
                ["adb", "shell", "pm", "path", package_name],
                capture_output=True, text=True, check=True
            )
            remote_paths = [line.replace("package:", "").strip() for line in result.stdout.strip().split("\n") if line]
            if not remote_paths:
                raise ValueError(f"No se encontraron APKs instalados para {package_name} en el dispositivo.")
                
            base_apk_remote = next((p for p in remote_paths if p.endswith("base.apk")), remote_paths[0])
            local_apk_path = work_dir / "base.apk"
            
            subprocess.run(["adb", "pull", base_apk_remote, str(local_apk_path)], check=True)
            apk_path = str(local_apk_path)
            
        if not apk_path:
            raise ValueError("No se pudo obtener una ruta de APK válida para analizar.")

        # Iniciar el análisis a través del sistema unificado
        active_tasks[task_id]['stage'] = 'analyzing'
        results = system.analyze(apk_path, device_connected=device_connected)
        
        if results.get('success'):
            active_tasks[task_id]['status'] = 'completed'
            active_tasks[task_id]['stage'] = 'done'
            active_tasks[task_id]['results'] = results
        else:
            active_tasks[task_id]['status'] = 'failed'
            active_tasks[task_id]['stage'] = 'error'
            active_tasks[task_id]['error'] = results.get('error', 'Error desconocido durante la ejecución.')
            
    except Exception as e:
        active_tasks[task_id]['status'] = 'failed'
        active_tasks[task_id]['stage'] = 'error'
        active_tasks[task_id]['error'] = str(e)


@app.route('/')
def index():
    # Obtener historial de APKs analizados desde los reportes JSON generados
    history = system.list_analyzed_apks()
    return render_template('index.html', history=history, active_tasks=active_tasks)


@app.route('/analyze/package', methods=['POST'])
def analyze_package():
    package_name = request.form.get('package_name', '').strip()
    device_connected = 'device_connected' in request.form
    
    if not package_name:
        return jsonify({'error': 'Debe especificar un nombre de paquete válido.'}), 400
        
    task_id = str(uuid.uuid4())
    active_tasks[task_id] = {
        'task_id': task_id,
        'target': package_name,
        'type': 'package',
        'status': 'queued',
        'stage': 'queued',
        'error': None
    }
    
    # Iniciar hilo de ejecución asíncrono
    thread = threading.Thread(
        target=run_analysis_in_background,
        args=(task_id, None, package_name, device_connected)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id, 'status': 'queued'})


@app.route('/analyze/file', methods=['POST'])
def analyze_file():
    if 'apk_file' not in request.files:
        return jsonify({'error': 'No se cargó ningún archivo.'}), 400
        
    file = request.files['apk_file']
    if file.filename == '':
        return jsonify({'error': 'Nombre de archivo vacío.'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        dest_path = UPLOAD_FOLDER / filename
        file.save(dest_path)
        
        task_id = str(uuid.uuid4())
        active_tasks[task_id] = {
            'task_id': task_id,
            'target': filename,
            'type': 'file',
            'status': 'queued',
            'stage': 'queued',
            'error': None
        }
        
        # Iniciar análisis asíncrono
        thread = threading.Thread(
            target=run_analysis_in_background,
            args=(task_id, str(dest_path), None, False)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'task_id': task_id, 'status': 'queued'})


@app.route('/tasks')
def list_tasks():
    return jsonify(active_tasks)


@app.route('/tasks/<task_id>')
def get_task_status(task_id):
    task = active_tasks.get(task_id)
    if not task:
        return jsonify({'error': 'Tarea no encontrada.'}), 404
    return jsonify(task)


@app.route('/report/view/<apk_hash>')
def view_report(apk_hash):
    # Encontrar el reporte markdown o JSON correspondiente al hash
    reports = list(system.reports_dir.glob(f"{apk_hash}_*.md"))
    if not reports:
        # Buscar en base a prefijos guardados
        reports = list(system.reports_dir.glob(f"*{apk_hash}*.md"))
        
    if not reports:
        return "Reporte no encontrado", 404
        
    # Leer el reporte Markdown y renderizarlo simple
    report_content = reports[0].read_text()
    
    # Un renderizado extremadamente simple de markdown para visualización
    return render_template('report.html', content=report_content, hash=apk_hash)


@app.route('/report/download/<apk_hash>/<format>')
def download_report(apk_hash, format):
    extension = f".{format}"
    reports = list(system.reports_dir.glob(f"*{apk_hash}*{extension}"))
    if not reports:
        return "Archivo de reporte no encontrado", 404
        
    return send_file(reports[0], as_attachment=True)


if __name__ == '__main__':
    # Ejecutar servidor local
    app.run(host='0.0.0.0', port=5000, debug=True)
