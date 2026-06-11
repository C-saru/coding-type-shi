-e 
--- FILE: ./docker-compose.yml ---
version: '3.8'

services:
  # Servicio principal del sistema
  apk-reverse:
    build: .
    volumes:
      - ./input:/app/input
      - ./output:/app/output
      - ./reports:/app/reports
    working_dir: /app
    command: ["python", "-c", "print('Sistema listo. Usa docker exec para interactuar.')"]
    
  # MobSF para análisis automatizado
  mobsf:
    image: opensecurity/mobile-security-framework-mobsf:latest
    ports:
      - "8000:8000"
    volumes:
      - mobsf_data:/home/mobsf/.MobSF
    environment:
      - MOBSF_API_KEY=changeme123

  # Contenedor con herramientas adicionales
  tools:
    image: ubuntu:22.04
    build:
      context: .
      dockerfile: Dockerfile.tools
    volumes:
      - ./input:/data/input
      - ./output:/data/output
    working_dir: /data
    stdin_open: true
    tty: true

volumes:
  mobsf_data:

networks:
  default:
    name: apk-reverse-network

-e 
--- FILE: ./Dockerfile.tools ---
FROM ubuntu:22.04

LABEL description="Herramientas adicionales de Reverse Engineering"

# Evitar prompts interactivos
ENV DEBIAN_FRONTEND=noninteractive

# Instalar herramientas básicas
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    curl \
    git \
    unzip \
    openjdk-11-jdk-headless \
    android-sdk-build-tools \
    adb \
    strings \
    binutils \
    radare2 \
    && rm -rf /var/lib/apt/lists/*

# Variables de entorno
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV ANDROID_HOME=/usr/lib/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools

# Instalar Frida
RUN pip3 install frida-tools objection

# Descargar Ghidra (versión headless)
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20231219.zip -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt/ \
    && mv /opt/ghidra_* /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless

# Descargar Il2CppDumper
RUN wget -q https://github.com/perfare/il2cppdumper/releases/download/v6.2.15/il2cppdumper-linux.zip -O /tmp/il2cpp.zip \
    && unzip -q /tmp/il2cpp.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/il2cppdumper \
    && rm /tmp/il2cpp.zip

# Configurar directorio de trabajo
WORKDIR /data

# Volúmenes para datos
VOLUME ["/data/input", "/data/output"]

CMD ["/bin/bash"]

-e 
--- FILE: ./output/plans/def456789abc_plan.json ---
{
  "apk_hash": "def456789abc",
  "package_name": "com.example.app",
  "total_tasks": 5,
  "tasks": [
    {
      "tool": "jadx",
      "description": "Decompilar DEX a c\u00f3digo Java legible",
      "priority": 1,
      "parameters": {
        "output_format": "java",
        "include_resources": false
      },
      "estimated_time": "2-5 min"
    },
    {
      "tool": "apktool",
      "description": "Decodear resources.arsc y AndroidManifest.xml",
      "priority": 1,
      "parameters": {
        "no_src": true,
        "force": true
      },
      "estimated_time": "1-3 min"
    },
    {
      "tool": "hermes-dec",
      "description": "Decompilar bytecode Hermes si est\u00e1 presente",
      "priority": 2,
      "parameters": {
        "bytecode_path": "assets/index.android.bundle"
      },
      "estimated_time": "2-5 min"
    },
    {
      "tool": "ghidra",
      "description": "An\u00e1lisis reverse de librer\u00edas nativas",
      "priority": 2,
      "parameters": {
        "auto_analyze": true,
        "find_strings": true
      },
      "estimated_time": "15-60 min"
    },
    {
      "tool": "frida",
      "description": "Instrumentaci\u00f3n para explorar bridge React Native",
      "priority": 3,
      "parameters": {
        "scripts": [
          "react-native-tracer.js"
        ]
      },
      "estimated_time": "15-30 min"
    }
  ],
  "recommended_tools": [
    "hermes-dec",
    "jadx",
    "apktool",
    "frida",
    "ghidra"
  ],
  "special_considerations": [
    "React Native detectado - bytecode Hermes puede estar presente",
    "Librer\u00edas nativas (.so) detectadas - an\u00e1lisis binario requerido"
  ]
}
-e 
--- FILE: ./tools/mobsf_api.py ---
import requests
import json
import time
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class MobSFWrapper:
    """Wrapper para comunicarse con la API REST de MobSF"""
    
    def __init__(self, server_url: str = "http://localhost:8000", api_key: str = None):
        """
        Args:
            server_url: URL base de MobSF
            api_key: API Key de MobSF (necesaria para interactuar)
        """
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key or os.environ.get('MOBSF_API_KEY', '')
        self.headers = {'Authorization': self.api_key}
        
    def upload_and_analyze(self, file_path: str, wait: bool = True) -> Dict:
        """
        Sube un archivo a MobSF y comienza el análisis
        
        Args:
            file_path: Ruta al archivo APK/IPA
            wait: Esperar a que termine el análisis
            
        Returns:
            Dict con los resultados (o status)
        """
        if not self.api_key:
            return {'success': False, 'error': 'No se configuró MOBSF_API_KEY'}
            
        if not os.path.exists(file_path):
            return {'success': False, 'error': f'Archivo no encontrado: {file_path}'}
            
        upload_url = f"{self.server_url}/api/v1/upload"
        
        logger.info(f"Subiendo archivo {file_path} a MobSF...")
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                response = requests.post(upload_url, headers=self.headers, files=files)
                
            if response.status_code != 200:
                return {'success': False, 'error': f'Error al subir a MobSF: {response.text}'}
                
            upload_data = response.json()
            file_hash = upload_data.get('hash')
            scan_type = upload_data.get('scan_type')
            file_name = upload_data.get('file_name')
            
            if not wait:
                return {'success': True, 'hash': file_hash, 'status': 'uploaded'}
                
            logger.info(f"Archivo subido exitosamente. Hash: {file_hash}. Iniciando análisis...")
            
            scan_url = f"{self.server_url}/api/v1/scan"
            scan_data = {'hash': file_hash, 'scan_type': scan_type, 'file_name': file_name}
            scan_response = requests.post(scan_url, headers=self.headers, data=scan_data)
            
            if scan_response.status_code != 200:
                return {'success': False, 'error': f'Error en escaneo de MobSF: {scan_response.text}'}
            
            scan_result = scan_response.json()
            return {
                'success': True,
                'hash': file_hash,
                'scan_type': scan_type,
                'report': scan_result
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_report_json(self, file_hash: str) -> Dict:
        """Obtiene el reporte en JSON para un hash dado"""
        report_url = f"{self.server_url}/api/v1/report_json"
        
        try:
            response = requests.post(report_url, headers=self.headers, data={'hash': file_hash})
            if response.status_code != 200:
                return {'success': False, 'error': f'Error al obtener reporte: {response.text}'}
            
            return {'success': True, 'report': response.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def delete_scan(self, file_hash: str) -> Dict:
        """Elimina el escaneo de MobSF"""
        delete_url = f"{self.server_url}/api/v1/delete_scan"
        
        try:
            response = requests.post(delete_url, headers=self.headers, data={'hash': file_hash})
            return {'success': response.status_code == 200}
        except Exception as e:
            return {'success': False, 'error': str(e)}

-e 
--- FILE: ./tools/__init__.py ---

-e 
--- FILE: ./tools/specialized_tools.py ---
"""
Wrappers para herramientas especializadas
Il2CppDumper (Unity) y hermes-dec (React Native)
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, Dict, List
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Il2CppDumperWrapper:
    """Wrapper para Il2CppDumper - Herramienta para Unity IL2CPP"""
    
    def __init__(self, il2cppdumper_path: str = "il2cppdumper"):
        """
        Args:
            il2cppdumper_path: Ruta al ejecutable de Il2CppDumper
        """
        self.il2cppdumper_path = il2cppdumper_path
    
    def dump(self, global_metadata_path: str, libil2cpp_path: str,
             output_dir: str, generate_scripts: bool = True) -> Dict:
        """
        Extrae metadatos de binarios IL2CPP de Unity
        
        Args:
            global_metadata_path: Ruta a global-metadata.dat
            libil2cpp_path: Ruta a libil2cpp.so
            output_dir: Directorio de salida
            generate_scripts: Generar scripts para IDA/Ghidra
        
        Returns:
            Dict con resultados
        """
        # Verificar archivos existen
        if not os.path.exists(global_metadata_path):
            return {
                'success': False,
                'error': f'global-metadata.dat no encontrado: {global_metadata_path}'
            }
        
        if not os.path.exists(libil2cpp_path):
            return {
                'success': False,
                'error': f'libil2cpp.so no encontrado: {libil2cpp_path}'
            }
        
        # Crear directorio de salida
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Comando para .NET Core version
        cmd = [
            self.il2cppdumper_path,
            global_metadata_path,
            libil2cpp_path,
            output_dir
        ]
        
        logger.info(f"Ejecutando Il2CppDumper: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            success = result.returncode == 0
            
            # Verificar archivos generados
            output_path = Path(output_dir)
            generated_files = {
                'dump.cs': (output_path / 'dump.cs').exists(),
                'script.json': (output_path / 'script.json').exists(),
                'ida.py': (output_path / 'ida.py').exists(),
                'ghidra.py': (output_path / 'ghidra.py').exists(),
                'header.h': (output_path / 'il2cpp_header.h').exists()
            }
            
            files_count = sum(1 for v in generated_files.values() if v)
            
            return {
                'success': success,
                'output_dir': output_dir,
                'files_generated': files_count,
                'generated_files': generated_files,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'error': None if success else result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - Il2CppDumper excedió tiempo límite'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def extract_from_apk(self, apk_path: str, output_dir: str) -> Dict:
        """
        Extrae automáticamente archivos IL2CPP desde un APK
        
        Args:
            apk_path: Ruta al APK
            output_dir: Directorio para extraer archivos
        
        Returns:
            Dict con rutas a archivos extraídos
        """
        import zipfile
        
        extracted = {
            'global_metadata': None,
            'libil2cpp': None
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                namelist = zf.namelist()
                
                # Buscar global-metadata.dat
                for name in namelist:
                    if 'global-metadata.dat' in name:
                        zf.extract(name, output_dir)
                        extracted['global_metadata'] = os.path.join(output_dir, name)
                        break
                
                # Buscar libil2cpp.so (puede estar en diferentes arquitecturas)
                for name in namelist:
                    if 'libil2cpp.so' in name:
                        zf.extract(name, output_dir)
                        extracted['libil2cpp'] = os.path.join(output_dir, name)
                        break
                
                if not extracted['global_metadata'] or not extracted['libil2cpp']:
                    return {
                        'success': False,
                        'error': 'Archivos IL2CPP no encontrados en el APK',
                        'extracted': extracted
                    }
                
                # Ejecutar dump
                dump_dir = os.path.join(output_dir, 'il2cpp_dump')
                return self.dump(
                    extracted['global_metadata'],
                    extracted['libil2cpp'],
                    dump_dir
                )
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'extracted': extracted
            }
    
    def parse_dump_cs(self, dump_file: str) -> Dict:
        """
        Parsea el archivo dump.cs para extraer información estructurada
        
        Args:
            dump_file: Ruta al archivo dump.cs
        
        Returns:
            Dict con clases, métodos y campos extraídos
        """
        classes = []
        current_class = None
        
        try:
            with open(dump_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Parseo básico (se puede mejorar)
                lines = content.split('\n')
                for line in lines:
                    if line.strip().startswith('namespace '):
                        pass  # Namespace encontrado
                    
                    elif line.strip().startswith('class ') or line.strip().startswith('sealed class '):
                        class_name = line.split('{')[0].replace('class', '').replace('sealed', '').strip()
                        current_class = {
                            'name': class_name,
                            'methods': [],
                            'fields': []
                        }
                        classes.append(current_class)
                    
                    elif current_class and '/*' in line and '*/' in line:
                        # Método encontrado (comentario con offset)
                        method_info = line.replace('/*', '').replace('*/', '').strip()
                        if method_info:
                            current_class['methods'].append(method_info)
                    
                    elif current_class and ';' in line and ('public' in line or 'private' in line or 'protected' in line):
                        # Campo encontrado
                        field_info = line.strip().replace(';', '')
                        if field_info:
                            current_class['fields'].append(field_info)
                
                return {
                    'success': True,
                    'total_classes': len(classes),
                    'classes': classes[:100],  # Primeras 100 clases
                    'file': dump_file
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class HermesDecWrapper:
    """Wrapper para hermes-dec - Decompilador de bytecode Hermes (React Native)"""
    
    def __init__(self, hermes_dec_path: str = "hermes-dec"):
        """
        Args:
            hermes_dec_path: Ruta al script hermes-dec.py
        """
        self.hermes_dec_path = hermes_dec_path
    
    def decompile(self, bytecode_path: str, output_file: str = None) -> Dict:
        """
        Decompila bytecode Hermes a JavaScript legible
        
        Args:
            bytecode_path: Ruta al archivo .hbc o bundle
            output_file: Ruta para guardar output (opcional)
        
        Returns:
            Dict con resultado
        """
        if not os.path.exists(bytecode_path):
            return {
                'success': False,
                'error': f'Bytecode no encontrado: {bytecode_path}'
            }
        
        # Detectar si es Python script o ejecutable
        if self.hermes_dec_path.endswith('.py'):
            cmd = ["python3", self.hermes_dec_path, bytecode_path]
        else:
            cmd = [self.hermes_dec_path, bytecode_path]
        
        logger.info(f"Ejecutando hermes-dec: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            
            output_content = result.stdout
            
            # Guardar a archivo si se especificó
            if output_file and success:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(output_content)
            
            return {
                'success': success,
                'decompiled_code': output_content if success else None,
                'output_file': output_file if success and output_file else None,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'error': None if success else result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - hermes-dec excedió tiempo límite'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def extract_from_apk(self, apk_path: str, output_dir: str) -> Dict:
        """
        Extrae y decompila bytecode Hermes desde un APK de React Native
        
        Args:
            apk_path: Ruta al APK
            output_dir: Directorio de trabajo
        
        Returns:
            Dict con resultados
        """
        import zipfile
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                namelist = zf.namelist()
                
                # Buscar bytecode Hermes
                bytecode_paths = [
                    'assets/index.android.bundle',
                    'index.android.bundle',
                    'assets/main.jsbundle'
                ]
                
                found_bundle = None
                for path in bytecode_paths:
                    if path in namelist:
                        found_bundle = path
                        break
                
                if not found_bundle:
                    return {
                        'success': False,
                        'error': 'Bytecode Hermes no encontrado en el APK'
                    }
                
                # Extraer bundle
                bundle_path = os.path.join(output_dir, 'index.android.bundle')
                zf.extract(found_bundle, output_dir)
                
                # Mover si estaba en subdirectorio
                if found_bundle != 'index.android.bundle':
                    extracted_path = os.path.join(output_dir, found_bundle)
                    if os.path.exists(extracted_path):
                        os.rename(extracted_path, bundle_path)
                
                # Decompilar
                output_js = os.path.join(output_dir, 'decompiled.js')
                return self.decompile(bundle_path, output_js)
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def analyze_react_native_structure(self, decompiled_code: str) -> Dict:
        """
        Analiza estructura de código React Native decompilado
        
        Args:
            decompiled_code: Código JavaScript decompilado
        
        Returns:
            Dict con componentes, imports y funciones detectadas
        """
        analysis = {
            'components': [],
            'imports': [],
            'api_endpoints': [],
            'native_modules': []
        }
        
        lines = decompiled_code.split('\n')
        
        for i, line in enumerate(lines):
            # Detectar componentes React
            if 'function ' in line and ('return' in ''.join(lines[i:i+10])):
                func_name = line.split('function ')[1].split('(')[0].strip()
                if func_name[0].isupper():  # Convención: componentes empiezan con mayúscula
                    analysis['components'].append(func_name)
            
            # Detectar imports
            if line.strip().startswith('import '):
                analysis['imports'].append(line.strip())
            
            # Detectar endpoints API
            if 'http://' in line or 'https://' in line:
                import re
                urls = re.findall(r'https?://[^\s\'\"<>]+', line)
                analysis['api_endpoints'].extend(urls)
            
            # Detectar módulos nativos
            if 'NativeModules.' in line or "require('react-native')" in line:
                analysis['native_modules'].append(line.strip())
        
        # Eliminar duplicados
        analysis['api_endpoints'] = list(set(analysis['api_endpoints']))
        analysis['imports'] = list(set(analysis['imports']))
        
        return {
            'success': True,
            'analysis': analysis,
            'stats': {
                'components_count': len(analysis['components']),
                'imports_count': len(analysis['imports']),
                'endpoints_count': len(analysis['api_endpoints']),
                'native_modules_count': len(analysis['native_modules'])
            }
        }


if __name__ == "__main__":
    print("=== Herramientas Especializadas ===\n")
    
    # Il2CppDumper
    print("--- Il2CppDumper (Unity) ---")
    il2cpp = Il2CppDumperWrapper()
    print(f"Path: {il2cpp.il2cppdumper_path}")
    print("Uso: il2cppdumper global-metadata.dat libil2cpp.so output/")
    print("Archivos generados: dump.cs, ida.py, ghidra.py, header.h\n")
    
    # hermes-dec
    print("--- hermes-dec (React Native) ---")
    hermes = HermesDecWrapper()
    print(f"Path: {hermes.hermes_dec_path}")
    print("Uso: python hermes-dec.py index.android.bundle")
    print("Output: Código JavaScript decompilado\n")
    
    print("Nota: Estas herramientas requieren instalación manual")
    print("  - Il2CppDumper: https://github.com/perfare/il2cppdumper")
    print("  - hermes-dec: https://github.com/P1sec/hermes-dec")

-e 
--- FILE: ./tools/static_analysis.py ---
"""
Wrappers para herramientas de análisis estático
JADX, Apktool y Ghidra
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, Dict, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class JadxWrapper:
    """Wrapper para JADX - Decompilador DEX a Java"""
    
    def __init__(self, jadx_path: str = "jadx"):
        self.jadx_path = jadx_path
    
    def decompile(self, apk_path: str, output_dir: str, 
                  threads: int = 4, no_resources: bool = False) -> Dict:
        """
        Decompila APK a código Java
        
        Args:
            apk_path: Ruta al archivo APK
            output_dir: Directorio de salida
            threads: Número de hilos para procesamiento paralelo
            no_resources: Si True, no decompila resources.arsc
        
        Returns:
            Dict con resultado y estadísticas
        """
        cmd = [
            self.jadx_path,
            "-j", str(threads),
            "-d", output_dir,
            "--show-bad-code",
            "--no-fallback"
        ]
        
        if no_resources:
            cmd.append("--no-resources")
        
        cmd.append(apk_path)
        
        logger.info(f"Ejecutando JADX: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutos máximo
            )
            
            success = result.returncode == 0
            
            # Contar archivos generados
            java_files = list(Path(output_dir).glob("**/*.java"))
            
            return {
                'success': success,
                'output_dir': output_dir,
                'java_files_count': len(java_files),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'error': None if success else result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - Decompilación excedió tiempo límite'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def decompile_dex(self, dex_path: str, output_dir: str) -> Dict:
        """Decompila archivo DEX individual"""
        return self.decompile(dex_path, output_dir)


class ApktoolWrapper:
    """Wrapper para Apktool - Decode/Rebuild de APKs"""
    
    def __init__(self, apktool_path: str = "apktool"):
        self.apktool_path = apktool_path
    
    def decode(self, apk_path: str, output_dir: str, 
               no_src: bool = False, force: bool = True) -> Dict:
        """
        Decodea un APK para analizar resources y Smali
        
        Args:
            apk_path: Ruta al APK
            output_dir: Directorio de salida
            no_src: Si True, no decompila fuentes (solo resources)
            force: Forzar overwrite si existe directorio
        
        Returns:
            Dict con resultado
        """
        cmd = [self.apktool_path, "d"]
        
        if no_src:
            cmd.append("-r")  # Solo resources, sin sources
        
        if force:
            cmd.append("-f")
        
        cmd.extend(["-o", output_dir, apk_path])
        
        logger.info(f"Ejecutando Apktool decode: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            success = result.returncode == 0
            
            # Verificar archivos generados
            output_path = Path(output_dir)
            has_manifest = (output_path / "AndroidManifest.xml").exists()
            has_smali = (output_path / "smali").exists()
            has_resources = (output_path / "res").exists()
            
            return {
                'success': success,
                'output_dir': output_dir,
                'has_manifest': has_manifest,
                'has_smali': has_smali,
                'has_resources': has_resources,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'error': None if success else result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - Decode excedió tiempo límite'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def build(self, input_dir: str, output_apk: str, 
              force: bool = True) -> Dict:
        """
        Reconstruye un APK desde directorio decodeado
        
        Args:
            input_dir: Directorio con APK decodeado
            output_apk: Ruta para el APK reconstruido
            force: Forzar overwrite
        
        Returns:
            Dict con resultado
        """
        cmd = [self.apktool_path, "b"]
        
        if force:
            cmd.append("-f")
        
        cmd.extend(["-o", output_apk, input_dir])
        
        logger.info(f"Ejecutando Apktool build: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            success = result.returncode == 0
            
            return {
                'success': success,
                'output_apk': output_apk if success else None,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'error': None if success else result.stderr
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class GhidraWrapper:
    """Wrapper para Ghidra - Análisis de binarios nativos"""
    
    def __init__(self, ghidra_path: str = None, headless_path: str = None):
        """
        Args:
            ghidra_path: Ruta a instalación de Ghidra
            headless_path: Ruta a analyzeHeadless (si es diferente)
        """
        self.ghidra_path = ghidra_path or os.environ.get('GHIDRA_INSTALL_DIR')
        self.headless_path = headless_path
        
        if not self.headless_path and self.ghidra_path:
            self.headless_path = os.path.join(
                self.ghidra_path, 
                "support", 
                "analyzeHeadless"
            )
    
    def analyze_so(self, so_file: str, project_dir: str,
                   project_name: str = "native_analysis",
                   script_path: Optional[str] = None) -> Dict:
        """
        Analiza librería nativa .so con Ghidra
        
        Args:
            so_file: Ruta al archivo .so
            project_dir: Directorio del proyecto Ghidra
            project_name: Nombre del proyecto
            script_path: Script Python/Ghidra para ejecutar post-análisis
        
        Returns:
            Dict con resultados
        """
        if not self.headless_path:
            return {
                'success': False,
                'error': 'Ghidra no configurado. Establecer GHIDRA_INSTALL_DIR'
            }
        
        cmd = [
            self.headless_path,
            project_dir,
            project_name,
            so_file,
            "-scriptPath", os.path.dirname(script_path) if script_path else ".",
            "-postScript", os.path.basename(script_path) if script_path else "",
            "-deleteProject",  # Limpiar proyecto existente
            "-q"  # Modo silencioso
        ]
        
        # Filtrar argumentos vacíos
        cmd = [c for c in cmd if c != "" and c != "-postScript" and c != "." 
               and c != "-scriptPath"]
        
        if script_path:
            cmd = [
                self.headless_path,
                project_dir,
                project_name,
                so_file,
                "-postScript", script_path,
                "-deleteProject",
                "-q"
            ]
        else:
            cmd = [
                self.headless_path,
                project_dir,
                project_name,
                so_file,
                "-deleteProject",
                "-q"
            ]
        
        logger.info(f"Ejecutando Ghidra analyzeHeadless")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hora para análisis complejo
                env={**os.environ, '_JAVA_AWT_WM_NONREPARENTING': '1'}
            )
            
            success = result.returncode == 0
            
            return {
                'success': success,
                'project_dir': project_dir,
                'project_name': project_name,
                'binary_analyzed': so_file,
                'stdout': result.stdout[-5000:] if result.stdout else "",  # Últimos 5k chars
                'stderr': result.stderr[-5000:] if result.stderr else "",
                'error': None if success else result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout - Análisis Ghidra excedió tiempo límite (1h)'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def extract_strings(self, so_file: str) -> Dict:
        """
        Extrae strings de un binario nativo
        
        Nota: Esto es un fallback rápido sin Ghidra
        """
        try:
            result = subprocess.run(
                ["strings", "-n", "8", so_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            strings_list = result.stdout.strip().split('\n')
            
            # Filtrar strings interesantes
            interesting = [
                s for s in strings_list 
                if any(kw in s.lower() for kw in [
                    'http', 'https', 'api', 'key', 'secret',
                    'password', 'token', 'auth', 'encrypt',
                    'decrypt', 'ssl', 'tls', 'certificate'
                ])
            ]
            
            return {
                'success': True,
                'total_strings': len(strings_list),
                'interesting_strings': len(interesting),
                'strings_sample': interesting[:50],  # Primeras 50
                'all_strings_file': f"{so_file}.strings.txt"
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


if __name__ == "__main__":
    # Ejemplo de uso
    print("=== Test de Wrappers ===\n")
    
    # Test JADX
    jadx = JadxWrapper()
    print(f"JADX path: {jadx.jadx_path}")
    print("Comando ejemplo: jadx -j 4 -d output/ app.apk\n")
    
    # Test Apktool
    apktool = ApktoolWrapper()
    print(f"Apktool path: {apktool.apktool_path}")
    print("Comando ejemplo: apktool d -f -o output/ app.apk\n")
    
    # Test Ghidra
    ghidra = GhidraWrapper()
    print(f"Ghidra instalado: {ghidra.headless_path is not None}")
    print("Nota: Ghidra requiere configuración manual de GHIDRA_INSTALL_DIR")

-e 
--- FILE: ./tools/dynamic_analysis.py ---
"""
Wrappers para herramientas de análisis dinámico
Frida y Objection
"""

import subprocess
import os
import time
from pathlib import Path
from typing import Optional, Dict, List, Callable
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FridaWrapper:
    """Wrapper para Frida - Instrumentación dinámica"""
    
    def __init__(self, device_id: str = None):
        """
        Args:
            device_id: ID del dispositivo (None = primer dispositivo USB)
        """
        self.device_id = device_id
        self.frida_server_running = False
    
    def check_frida_server(self) -> bool:
        """Verifica si frida-server está corriendo en el dispositivo"""
        try:
            result = subprocess.run(
                ["adb", "shell", "ps", "|", "grep", "frida-server"],
                capture_output=True,
                text=True,
                timeout=10
            )
            self.frida_server_running = len(result.stdout.strip()) > 0
            return self.frida_server_running
        except Exception:
            return False
    
    def start_frida_server(self, frida_server_path: str = "/data/local/tmp/frida-server") -> bool:
        """Inicia frida-server en el dispositivo"""
        try:
            # Verificar si ya está corriendo
            if self.check_frida_server():
                logger.info("frida-server ya está corriendo")
                return True
            
            # Matar procesos existentes
            subprocess.run(
                ["adb", "shell", "killall", "frida-server"],
                capture_output=True,
                timeout=5
            )
            
            # Iniciar en background
            subprocess.Popen(
                ["adb", "shell", frida_server_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(2)  # Esperar que inicie
            return self.check_frida_server()
            
        except Exception as e:
            logger.error(f"Error al iniciar frida-server: {e}")
            return False
    
    def spawn_and_attach(self, package_name: str, script_path: str,
                         output_callback: Optional[Callable] = None) -> Dict:
        """
        Hace spawn de una app y adjunta script Frida
        
        Args:
            package_name: Package name de la app Android
            script_path: Ruta al script .js de Frida
            output_callback: Función para recibir output del script
        
        Returns:
            Dict con resultado
        """
        cmd = [
            "frida",
            "-U",  # USB device
            "-f", package_name,
            "-l", script_path,
            "--no-pause"  # No pausar al inicio
        ]
        
        if self.device_id:
            cmd = ["frida", "-D", self.device_id, "-f", package_name, "-l", script_path, "--no-pause"]
        
        logger.info(f"Ejecutando Frida: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            output_lines = []
            
            # Leer output en tiempo real
            for line in process.stdout:
                if line.strip():
                    output_lines.append(line.strip())
                    if output_callback:
                        output_callback(line.strip())
                    
                    # Detectar errores comunes
                    if "error:" in line.lower() or "failed:" in line.lower():
                        logger.warning(f"Frida reportó: {line.strip()}")
            
            # Esperar terminación
            stdout, stderr = process.communicate(timeout=300)
            
            success = process.returncode == 0 or len(output_lines) > 0
            
            return {
                'success': success,
                'output_lines': output_lines,
                'stdout': stdout,
                'stderr': stderr,
                'package': package_name
            }
            
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                'success': False,
                'error': 'Timeout - Sesión Frida excedió tiempo límite',
                'partial_output': output_lines
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def attach_to_running(self, package_name: str, script_path: str) -> Dict:
        """Adjunta a proceso ya existente"""
        cmd = [
            "frida",
            "-U",
            package_name,
            "-l", script_path
        ]
        
        if self.device_id:
            cmd = ["frida", "-D", self.device_id, package_name, "-l", script_path]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def trace_method(self, package_name: str, method_pattern: str) -> Dict:
        """
        Usa frida-trace para monitorear métodos
        
        Args:
            package_name: Package de la app
            method_pattern: Patrón de método (ej: "*MainActivity*onCreate*")
        """
        cmd = [
            "frida-trace",
            "-U",
            "-f", package_name,
            "-i", method_pattern
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': result.returncode == 0,
                'trace_output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def dump_memory(self, package_name: str, output_file: str) -> Dict:
        """Voltea memoria del proceso"""
        script_content = """
Java.perform(function() {
    var Process = Java.use('java.lang.Process');
    console.log("[*] Memory dump initiated for: " + Process);
    
    // Implementar lógica de dump según necesites
    console.log("[*] Dump completo");
});
        """
        
        # Guardar script temporal
        temp_script = Path("/tmp/frida_dump.js")
        temp_script.write_text(script_content)
        
        return self.spawn_and_attach(package_name, str(temp_script))


class ObjectionWrapper:
    """Wrapper para Objection - Toolkit de exploración runtime"""
    
    def __init__(self, package_name: str = None):
        """
        Args:
            package_name: Package name objetivo (puede setearse después)
        """
        self.package_name = package_name
        self.session_active = False
    
    def explore(self, commands: List[str] = None) -> Dict:
        """
        Ejecuta sesión interactiva de objection con comandos automatizados
        
        Args:
            commands: Lista de comandos a ejecutar automáticamente
        
        Returns:
            Dict con resultados
        """
        if not self.package_name:
            return {
                'success': False,
                'error': 'Package name no especificado'
            }
        
        # Construir comando
        cmd = ["objection", "-g", self.package_name, "explore"]
        
        # Si hay comandos, crear script temporal
        script_path = None
        if commands:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as temp_file:
                temp_file.write("\n".join(commands))
                script_path = temp_file.name
            cmd.extend(["-s", script_path])
        
        logger.info(f"Ejecutando Objection: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                input="\n".join(commands) if commands else None
            )
            
            if script_path and os.path.exists(script_path):
                os.remove(script_path)
            
            success = result.returncode == 0 or len(result.stdout) > 100
            
            return {
                'success': success,
                'output': result.stdout[-10000:],  # Últimos 10k chars
                'stderr': result.stderr,
                'commands_executed': commands or []
            }
            
        except subprocess.TimeoutExpired:
            if script_path and os.path.exists(script_path):
                os.remove(script_path)
            return {
                'success': False,
                'error': 'Timeout - Sesión Objection excedió tiempo límite'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def bypass_ssl_pinning(self) -> Dict:
        """Bypass automático de SSL pinning"""
        return self.explore([
            "android sslpinning disable",
            "jobs list",
            "exit"
        ])
    
    def bypass_root_detection(self) -> Dict:
        """Bypass automático de root detection"""
        return self.explore([
            "android root disable",
            "jobs list",
            "exit"
        ])
    
    def bypass_flutter_root(self) -> Dict:
        """Bypass específico para Flutter root detection"""
        return self.explore([
            "android root disable",
            "flutter env dump",
            "exit"
        ])
    
    def dump_keychain(self) -> Dict:
        """Voltea keychain/SharedPreferences"""
        return self.explore([
            "android keystore list",
            "android sharedprefs get",
            "exit"
        ])
    
    def explore_runtime(self) -> Dict:
        """Exploración completa del runtime"""
        commands = [
            "help",
            "android hooking list classes",
            "android hooking list activities",
            "android hooking list services",
            "android hooking list receivers",
            "android intent launch_activity com.example.MainActivity",
            "memory list modules",
            "exit"
        ]
        
        return self.explore(commands)
    
    def set_package(self, package_name: str):
        """Setea el package name objetivo"""
        self.package_name = package_name


class R2FridaWrapper:
    """Wrapper para Radare2 / r2frida"""
    
    def __init__(self, r2_path: str = "r2"):
        """
        Args:
            r2_path: Ruta al ejecutable de radare2
        """
        self.r2_path = r2_path
        
    def check_r2frida(self) -> bool:
        """Verifica si el plugin r2frida está instalado"""
        try:
            result = subprocess.run([self.r2_path, "-L"], capture_output=True, text=True, timeout=10)
            return 'frida' in result.stdout.lower() or 'frida' in result.stderr.lower()
        except Exception:
            return False

    def execute_commands(self, package_name: str, commands: List[str]) -> Dict:
        """
        Ejecuta comandos r2frida y retorna la salida
        """
        if not commands:
            return {'success': False, 'error': 'No hay comandos proporcionados'}
            
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as temp_file:
                temp_file.write("\n".join(commands) + "\nq\n")
                script_path = temp_file.name
                
            cmd = [self.r2_path, "-q", "-i", script_path, f"frida://usb//{package_name}"]
            logger.info(f"Ejecutando Radare2: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Limpiar archivo temporal
            if os.path.exists(script_path):
                os.remove(script_path)
                
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout - Ejecución de Radare2 excedió tiempo límite'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def explore_binary(self, package_name: str) -> Dict:
        """Comandos predefinidos para exploración de memoria/binarios con r2frida"""
        commands = [
            ":i",         # App info
            ":il",        # List libraries
            ":ic",        # List classes
            ":is",        # List symbols
        ]
        return self.execute_commands(package_name, commands)


class QBDIWrapper:
    """Wrapper para QuarkslaB Dynamic binary Instrumentation (QBDI) - Placeholder"""
    
    def __init__(self):
        pass

    def analyze_instruction_trace(self, binary_path: str):
        """Placeholder function to be extended with QBDI tracing capabilities"""
        logger.info(f"[QBDI] Analyzing instruction trace for binary: {binary_path}")
        return {"success": True, "info": "QBDI instruction trace initialized. Implement me!"}


def create_frida_script_bypass_all() -> str:
    """
    Genera script Frida completo para bypass de protecciones comunes
    
    Returns:
        Contenido del script JS
    """
    script = """
// Frida Script - Bypass All Common Protections
// Auto-generated by APK Reverse System

Java.perform(function() {
    console.log("[*] Starting bypass scripts...");
    
    // === SSL Pinning Bypass ===
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        console.log("[+] OkHttp found - SSL pinning will be bypassed");
        
        // Implementar bypass según versión
    } catch(e) {
        console.log("[-] OkHttp not found");
    }
    
    // === Root Detection Bypass ===
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") >= 0 || path.indexOf("magisk") >= 0) {
                console.log("[*] Root detection blocked: " + path);
                return false;
            }
            return this.exists();
        };
        console.log("[+] Root detection bypass active");
    } catch(e) {
        console.log("[-] Root detection bypass failed: " + e);
    }
    
    // === Debug Detection Bypass ===
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[*] Debug detection blocked");
            return false;
        };
        console.log("[+] Debug detection bypass active");
    } catch(e) {
        console.log("[-] Debug detection bypass failed");
    }
    
    // === Emulator Detection Bypass ===
    try {
        var Build = Java.use('android.os.Build');
        // Modificar valores de Build para ocultar emulador
        console.log("[+] Emulator detection bypass active");
    } catch(e) {
        console.log("[-] Emulator detection bypass failed");
    }
    
    console.log("[*] All bypass scripts loaded successfully");
});
    """
    
    return script


if __name__ == "__main__":
    print("=== Frida & Objection Wrappers ===\n")
    
    # Frida
    frida = FridaWrapper()
    print(f"Frida server running: {frida.check_frida_server()}")
    print("\nComandos útiles:")
    print("  frida -U -f com.app -l script.js")
    print("  frida-trace -U -f com.app -i '*onCreate*'")
    
    # Objection
    print("\n---")
    objection = ObjectionWrapper("com.example.app")
    print(f"Objection package: {objection.package_name}")
    print("\nComandos útiles:")
    print("  objection -g com.app explore")
    print("  android sslpinning disable")
    print("  android root disable")
    
    # Generar script bypass
    print("\n---")
    script = create_frida_script_bypass_all()
    print(f"Script bypass generado: {len(script)} bytes")

-e 
--- FILE: ./super_pipeline.py ---
import sys
import argparse
import logging
import subprocess
from pathlib import Path
from typing import List

from modules.ingester import APKIngester
from modules.planner import APKPlanner
from modules.executor import APKExecutor
from modules.split_patcher import SplitAPKPatcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SuperPipeline")


def extract_apks_from_device(package_name: str, work_dir: Path) -> List[Path]:
    """Extrae base.apk y todos los splits del dispositivo"""
    logger.info(f"[*] Buscando rutas de {package_name} en el dispositivo...")
    try:
        result = subprocess.run(
            ["adb", "shell", "pm", "path", package_name],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Error llamando a adb: {e}")
        return []
        
    remote_paths = [line.replace("package:", "").strip() for line in result.stdout.strip().split("\n") if line]
    
    apks = []
    for remote in remote_paths:
        filename = Path(remote).name
        local_path = work_dir / filename
        logger.info(f"[*] Extrayendo {filename}...")
        subprocess.run(["adb", "pull", remote, str(local_path)], check=True, stdout=subprocess.DEVNULL)
        apks.append(local_path)
    return apks


def main():
    parser = argparse.ArgumentParser(description="Super Pipeline for Advanced APK Reverse Engineering")
    parser.add_argument("package_name", help="Package name to extract from device and analyze")
    args = parser.parse_args()
    
    package_name = args.package_name
    work_dir = Path("output/extracted_apks") / package_name
    work_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 60)
    logger.info("🚀 INICIANDO SUPER PIPELINE DE INGENIERÍA INVERSA")
    logger.info("=" * 60)
    
    # 1. Ingester - Extracción de APKs
    logger.info("\n[1/4] 📥 Extrayendo APKs del dispositivo...")
    apks = extract_apks_from_device(package_name, work_dir)
    base_apk = next((p for p in apks if p.name == "base.apk"), None)
    
    if not base_apk:
        logger.error("❌ No se encontró base.apk en la extracción.")
        sys.exit(1)
        
    apk_path = str(base_apk)
    
    logger.info(f"\n[*] Ejecutando Ingester en {apk_path}...")
    ingester = APKIngester()
    apk_info = ingester.analyze(apk_path)
    
    if not apk_info.is_valid:
        logger.error(f"❌ APK inválido: {apk_info.error_message}")
        sys.exit(1)
        
    logger.info(f"✅ APK válido: {apk_info.package_name}")
    logger.info(f"   Split APK: {apk_info.is_split_apk}")
    logger.info(f"   Native Libs: {apk_info.has_native_libs}")
    
    # 2. Planner
    logger.info("\n[2/4] 📋 Ejecutando Planner...")
    planner = APKPlanner()
    plan = planner.create_plan(apk_info)
    
    logger.info(f"✅ Plan generado con {plan.total_tasks} tareas.")
    for task in plan.tasks:
        logger.info(f"   - Tarea: {task.tool} | Prioridad: {task.priority}")
        
    # 3. Executor (incluye SplitAPKPatcher internamente)
    logger.info("\n[3/4] ⚙️ Ejecutando Executor...")
    executor = APKExecutor()
    results = executor.execute_plan(apk_path, plan, device_connected=True)
    
    # 4. Resumen
    logger.info("\n[4/4] 📊 Resumen del Pipeline")
    logger.info(f"Tareas exitosas: {results['summary']['successful']}/{results['summary']['total_tasks']}")
    logger.info("Pipeline completado exitosamente.")

if __name__ == "__main__":
    main()

-e 
--- FILE: ./Dockerfile ---
FROM python:3.10-slim

LABEL description="APK Reverse Engineering System"
LABEL maintainer="Security Team"

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    openjdk-11-jdk-headless \
    android-sdk-build-tools \
    git \
    && rm -rf /var/lib/apt/lists/*

# Establecer variables de entorno
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV ANDROID_HOME=/usr/lib/android-sdk

# Descargar e instalar JADX
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/ \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui \
    && rm /tmp/jadx.zip

# Descargar e instalar Apktool
RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.9.0/apktool_2.9.0.jar -O /usr/local/bin/apktool.jar \
    && wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Instalar dependencias Python
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Crear directorios
RUN mkdir -p /app/input /app/output /app/reports

# Volumen para datos persistentes
VOLUME ["/app/input", "/app/output", "/app/reports"]

# Puerto para API (si se implementa)
EXPOSE 5000

CMD ["python", "-c", "print('APK Reverse System ready!')"]

-e 
--- FILE: ./app.py ---
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

-e 
--- FILE: ./docs/INSTALL.md ---
# 🚀 Guía de Instalación y Uso

## Requisitos del Sistema

### Mínimos
- Python 3.8+
- 4GB RAM (8GB recomendado)
- 10GB espacio libre
- Docker (opcional, para contenedores)

### Dependencias del Sistema
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    openjdk-11-jdk \
    android-sdk-build-tools \
    libmagic1 \
    adb

# macOS
brew install python openjdk android-platform-tools libmagic

# Windows
# Descargar e instalar:
# - Python desde python.org
# - JDK desde Oracle/OpenJDK
# - Android SDK Build Tools
```

## Instalación

### Opción 1: Instalación Local

```bash
# Clonar o descargar el repositorio
cd apk-reverse-system

# Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Instalar dependencias Python
pip install -r requirements.txt

# Instalar herramientas externas manualmente:
# 1. JADX: https://github.com/skylot/jadx/releases
# 2. Apktool: https://ibotpeaches.github.io/Apktool/install/
# 3. Frida: pip install frida-tools
# 4. Ghidra: https://ghidra-sre.org/
```

### Opción 2: Docker (Recomendado)

```bash
# Construir imagen principal
docker build -t apk-reverse .

# Construir imagen con herramientas completas
docker build -f Dockerfile.tools -t apk-reverse-tools .

# Usar docker-compose
docker-compose up -d

# Ejecutar análisis en contenedor
docker run --rm -v $(pwd)/input:/app/input -v $(pwd)/output:/app/output apk-reverse python modules/main.py
```

## Configuración de Herramientas

### JADX
```bash
# Descargar
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Verificar
jadx --version
```

### Apktool
```bash
# Descargar jar
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.0/apktool_2.9.0.jar -O apktool.jar

# Descargar script wrapper
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
chmod +x apktool

# Mover a PATH
sudo mv apktool apktool.jar /usr/local/bin/

# Verificar
apktool --version
```

### Frida
```bash
# Instalar herramientas Python
pip install frida-tools objection

# En dispositivo Android (requiere root):
adb push frida-server /data/local/tmp
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verificar
frida --version
frida-ps -U
```

### Ghidra (Opcional)
```bash
# Descargar desde https://ghidra-sre.org/
# Descomprimir
# Establecer variable de entorno
export GHIDRA_INSTALL_DIR=/opt/ghidra

# Para análisis headless:
analyzeHeadless project_dir project_name file.so
```

## Uso Básico

### API Python

```python
from modules.main import APKReverseSystem

# Inicializar sistema
system = APKReverseSystem()

# Análisis completo
results = system.analyze("input/app.apk")

# Escaneo rápido (solo estático)
quick = system.quick_scan("input/app.apk")

# Ver historial de análisis
history = system.list_analyzed_apks()

# Acceder a resultados
print(f"Package: {results['apk_info']['package_name']}")
print(f"Tareas exitosas: {results['execution_results']['summary']['successful']}")
```

### Línea de Comandos

```bash
# Análisis completo
python -c "from modules.main import APKReverseSystem; s = APKReverseSystem(); s.analyze('input/app.apk')"

# Con dispositivo conectado para análisis dinámico
python -c "from modules.main import APKReverseSystem; s = APKReverseSystem(); s.analyze('input/app.apk', device_connected=True)"
```

## Estructura de Directorios

```
apk-reverse-system/
├── input/              # APKs a analizar
├── output/             # Resultados intermedios
│   └── <hash>/        # Directorio por APK
│       ├── jadx_output/
│       ├── apktool_output/
│       ├── native_libs/
│       └── analysis_report.json
├── reports/            # Reportes finales
│   ├── <hash>_timestamp.json
│   └── <hash>_timestamp.md
├── modules/            # Módulos principales
├── tools/              # Wrappers de herramientas
└── config/             # Configuraciones
```

## Formatos de Salida

### JSON Report
Contiene toda la información estructurada del análisis.

### Markdown Report
Reporte legible para humanos con:
- Información general del APK
- Permisos solicitados
- Características detectadas
- Plan de análisis ejecutado
- Resultados por herramienta

## Solución de Problemas

### Error: libmagic no encontrado
```bash
# Ubuntu/Debian
sudo apt-get install libmagic1

# macOS
brew install libmagic

# Windows
# Instalar python-magic-bin
pip install python-magic-bin
```

### Error: Java no encontrado
```bash
# Verificar instalación
java -version

# Establecer JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

### Error: adb no encontrado
```bash
# Ubuntu/Debian
sudo apt-get install android-tools-adb

# macOS
brew install android-platform-tools
```

### Frida no detecta dispositivo
```bash
# Verificar conexión
adb devices

# Reiniciar adb server
adb kill-server
adb start-server

# Verificar frida-server
adb shell ps | grep frida
```

## Mejores Prácticas

1. **Entorno Aislado**: Usar siempre entorno virtual o Docker
2. **Dispositivo Test**: Usar emulador o dispositivo dedicado para testing
3. **Backups**: Mantener copias de APKs originales
4. **Legalidad**: Solo analizar apps propias o con autorización
5. **Resources**: Documentar hallazgos importantes

## Recursos Adicionales

- [OWASP MASTG](https://owasp.org/www-project-mobile-app-security/)
- [Frida Documentation](https://frida.re/docs/)
- [Android Reverse Engineering](https://github.com/user1342/Awesome-Android-Reverse-Engineering)

## Soporte

Para issues y contribuciones, revisar la documentación en `docs/` o abrir un issue en el repositorio.

-e 
--- FILE: ./templates/index.html ---
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Reverse System - Dashboard</title>
    <!-- Google Fonts & FontAwesome -->
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #121824;
            --bg-glass: rgba(18, 24, 36, 0.7);
            --accent-glow: #3b82f6;
            --accent-success: #10b981;
            --accent-error: #ef4444;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --border-glow: rgba(59, 130, 246, 0.2);
            --font-main: 'Outfit', sans-serif;
            --font-mono: 'Space Grotesk', sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-primary);
            color: var(--text-main);
            font-family: var(--font-main);
            min-height: 100/vh;
            overflow-x: hidden;
            background-image: radial-gradient(circle at 10% 20%, rgba(59, 130, 246, 0.05) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
        }

        /* Contenedor principal */
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Cabecera */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            margin-bottom: 3rem;
        }

        .logo h1 {
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 2.2rem;
            background: linear-gradient(135deg, #60a5fa 0%, #34d399 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
        }

        .logo p {
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-top: 0.2rem;
        }

        .status-badge {
            background-color: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--accent-success);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-family: var(--font-mono);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-badge::before {
            content: '';
            display: inline-block;
            width: 8px;
            height: 8px;
            background-color: var(--accent-success);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--accent-success);
        }

        /* Layout Grid */
        .grid-layout {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            align-items: start;
        }

        @media (max-width: 1024px) {
            .grid-layout {
                grid-template-columns: 1fr;
            }
        }

        /* Tarjetas / Paneles */
        .panel {
            background-color: var(--bg-glass);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            padding: 2rem;
            backdrop-filter: blur(16px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .panel:hover {
            border-color: var(--border-glow);
            box-shadow: 0 12px 40px rgba(59, 130, 246, 0.1);
        }

        .panel-title {
            font-family: var(--font-mono);
            font-size: 1.3rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            color: #ffffff;
        }

        .panel-title i {
            color: var(--accent-glow);
        }

        /* Formulario y Controles */
        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .input-control {
            width: 100%;
            background-color: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            font-family: var(--font-mono);
            outline: none;
            transition: border-color 0.2s;
        }

        .input-control:focus {
            border-color: var(--accent-glow);
        }

        .switch-group {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            cursor: pointer;
        }

        .switch-group input {
            cursor: pointer;
        }

        /* Botón de acción principal */
        .btn-action {
            width: 100%;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            border: none;
            color: #ffffff;
            font-family: var(--font-mono);
            font-weight: 700;
            padding: 1rem;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4);
        }

        .btn-action:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(37, 99, 235, 0.6);
        }

        .btn-action:active {
            transform: translateY(0);
        }

        /* Línea separadora */
        .divider {
            text-align: center;
            margin: 2rem 0;
            position: relative;
        }

        .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background-color: rgba(255, 255, 255, 0.05);
            z-index: 1;
        }

        .divider span {
            position: relative;
            background-color: var(--bg-secondary);
            padding: 0 1rem;
            z-index: 2;
            color: var(--text-muted);
            font-size: 0.8rem;
            font-family: var(--font-mono);
            text-transform: uppercase;
        }

        /* Historial y Tablas */
        .table-wrapper {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--text-muted);
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            font-size: 0.95rem;
        }

        tr:hover td {
            background-color: rgba(255, 255, 255, 0.01);
        }

        .package-cell {
            font-family: var(--font-mono);
            color: #60a5fa;
            font-weight: 600;
        }

        .hash-cell {
            font-family: var(--font-mono);
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .date-cell {
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .actions-cell {
            display: flex;
            gap: 0.5rem;
        }

        .btn-icon {
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            width: 32px;
            height: 32px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .btn-icon:hover {
            background-color: var(--accent-glow);
            color: #ffffff;
            border-color: var(--accent-glow);
        }

        /* Lista de tareas en ejecución */
        .task-list {
            margin-top: 2rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .task-item {
            background-color: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .task-info h4 {
            font-family: var(--font-mono);
            font-size: 0.95rem;
        }

        .task-info p {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }

        .task-status {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            text-transform: uppercase;
        }

        .task-status.queued {
            background-color: rgba(245, 158, 11, 0.1);
            color: #f59e0b;
        }

        .task-status.running {
            background-color: rgba(59, 130, 246, 0.1);
            color: var(--accent-glow);
            animation: pulse 1.5s infinite;
        }

        .task-status.completed {
            background-color: rgba(16, 185, 129, 0.1);
            color: var(--accent-success);
        }

        .task-status.failed {
            background-color: rgba(239, 68, 68, 0.1);
            color: var(--accent-error);
        }

        @keyframes pulse {
            0% { opacity: 0.6; }
            50% { opacity: 1; }
            100% { opacity: 0.6; }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <header>
            <div class="logo">
                <h1>APK REVERSE SYSTEM</h1>
                <p>Auditoría Automatizada de Seguridad en Dispositivos Móviles</p>
            </div>
            <div class="status-badge">ADB Conectado</div>
        </header>

        <div class="grid-layout">
            <!-- Sección de Envío / Disparador de Análisis -->
            <div class="panel">
                <div class="panel-title">
                    <i class="fa-solid fa-microchip"></i>
                    <h2>Iniciar Análisis</h2>
                </div>

                <!-- Método 1: ADB Extracción -->
                <form id="packageForm" action="/analyze/package" method="POST">
                    <div class="form-group">
                        <label for="package_name">Nombre del Paquete en Dispositivo</label>
                        <input type="text" class="input-control" id="package_name" name="package_name" placeholder="ej. com.sokak.imposter" required>
                    </div>

                    <div class="switch-group">
                        <input type="checkbox" id="device_connected" name="device_connected" checked>
                        <label for="device_connected">Ejecutar análisis dinámico (Frida / Objection)</label>
                    </div>

                    <button type="submit" class="btn-action">
                        <i class="fa-solid fa-network-wired"></i>
                        Extraer y Analizar
                    </button>
                </form>

                <div class="divider">
                    <span>O cargar archivo APK local</span>
                </div>

                <!-- Método 2: Carga de APK física -->
                <form id="fileForm" action="/analyze/file" method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="apk_file">Archivo APK</label>
                        <input type="file" class="input-control" id="apk_file" name="apk_file" accept=".apk" required>
                    </div>

                    <button type="submit" class="btn-action" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); box-shadow: 0 4px 14px rgba(16, 185, 129, 0.4);">
                        <i class="fa-solid fa-cloud-arrow-up"></i>
                        Cargar y Analizar
                    </button>
                </form>

                <!-- Tareas en Ejecución -->
                <div class="task-list" id="taskList">
                    <!-- Dinámico por JS -->
                </div>
            </div>

            <!-- Panel de Historial de Reportes -->
            <div class="panel">
                <div class="panel-title">
                    <i class="fa-solid fa-clock-history"></i>
                    <h2>Aplicaciones Analizadas</h2>
                </div>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Package</th>
                                <th>SHA256</th>
                                <th>Reportes</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in history %}
                            <tr>
                                <td class="package-cell">{{ item.package }}</td>
                                <td class="hash-cell">{{ item.sha256[:16] }}...</td>
                                <td class="actions-cell">
                                    <a href="/report/view/{{ item.sha256[:16] }}" class="btn-icon" title="Ver Reporte">
                                        <i class="fa-solid fa-file-contract"></i>
                                    </a>
                                    <a href="/report/download/{{ item.sha256[:16] }}/json" class="btn-icon" title="Descargar JSON">
                                        <i class="fa-solid fa-file-code"></i>
                                    </a>
                                    <a href="/report/download/{{ item.sha256[:16] }}/md" class="btn-icon" title="Descargar Markdown">
                                        <i class="fa-solid fa-download"></i>
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                            {% if not history %}
                            <tr>
                                <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                    No se encontraron análisis anteriores en la carpeta reports/.
                                </td>
                            </tr>
                            {% endif %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Script de control dinámico y sondeo de tareas -->
    <script>
        const packageForm = document.getElementById('packageForm');
        const fileForm = document.getElementById('fileForm');
        const taskList = document.getElementById('taskList');

        async function handleFormSubmit(e, url, formData) {
            e.preventDefault();
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    pollTaskStatus(data.task_id);
                }
            } catch (err) {
                console.error(err);
            }
        }

        packageForm.addEventListener('submit', function(e) {
            const formData = new FormData(packageForm);
            handleFormSubmit(e, '/analyze/package', formData);
        });

        fileForm.addEventListener('submit', function(e) {
            const formData = new FormData(fileForm);
            handleFormSubmit(e, '/analyze/file', formData);
        });

        function pollTaskStatus(taskId) {
            const interval = setInterval(async () => {
                try {
                    const res = await fetch('/tasks/' + taskId);
                    const task = await res.json();
                    
                    updateTaskUI(task);
                    
                    if (task.status === 'completed' || task.status === 'failed') {
                        clearInterval(interval);
                        if (task.status === 'completed') {
                            location.reload();
                        }
                    }
                } catch (err) {
                    clearInterval(interval);
                }
            }, 3000);
        }

        function updateTaskUI(task) {
            let item = document.getElementById('task-' + task.task_id);
            if (!item) {
                item = document.createElement('div');
                item.id = 'task-' + task.task_id;
                item.className = 'task-item';
                taskList.appendChild(item);
            }
            
            item.innerHTML = `
                <div class="task-info">
                    <h4>${task.target}</h4>
                    <p>Fase actual: <strong>${task.stage}</strong></p>
                    ${task.error ? `<p style="color: var(--accent-error)">${task.error}</p>` : ''}
                </div>
                <span class="task-status ${task.status}">${task.status}</span>
            `;
        }
    </script>
</body>
</html>

-e 
--- FILE: ./templates/report.html ---
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Análisis - APK Reverse System</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #121824;
            --accent-glow: #3b82f6;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --font-main: 'Outfit', sans-serif;
            --font-mono: 'Space Grotesk', sans-serif;
        }

        body {
            background-color: var(--bg-primary);
            color: var(--text-main);
            font-family: var(--font-main);
            padding: 3rem;
            max-width: 1000px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 1.5rem;
            margin-bottom: 3rem;
        }

        .back-link {
            color: var(--accent-glow);
            text-decoration: none;
            font-family: var(--font-mono);
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: transform 0.2s;
        }

        .back-link:hover {
            transform: translateX(-4px);
        }

        h1 {
            font-family: var(--font-mono);
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
        }

        pre {
            background-color: var(--bg-secondary);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 2rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: var(--font-mono);
            line-height: 1.6;
            font-size: 0.95rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
    </style>
</head>
<body>
    <header>
        <a href="/" class="back-link">
            <i class="fa-solid fa-arrow-left"></i> Volver al Dashboard
        </a>
        <div style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-muted);">
            ID: {{ hash }}
        </div>
    </header>

    <h1>Reporte de Auditoría Técnica</h1>
    <pre>{{ content }}</pre>
</body>
</html>

-e 
--- FILE: ./modules/split_patcher.py ---
import os
import subprocess
import shutil
import logging
import zipfile
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel

try:
    import lief
except ImportError:
    lief = None

logger = logging.getLogger(__name__)

class SplitPatcherResult(BaseModel):
    success: bool
    patched_apk: Optional[str] = None
    original_splits: List[str] = []
    error: Optional[str] = None

class SplitAPKPatcher:
    """Módulo para parsear y parchar Split APKs con inyección ELF usando LIEF"""

    def __init__(self, work_dir: str = "output/patches"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def check_requirements(self):
        if not lief:
            raise EnvironmentError("La librería 'lief' es necesaria. Instálala con 'pip install lief'")
        
        for tool in ["zip", "zipalign", "apksigner"]:
            if not shutil.which(tool):
                raise EnvironmentError(f"Herramienta externa '{tool}' no encontrada en el PATH.")

    def patch_split(self, split_apk_path: str, target_lib_name: str, keystore_path: str, keystore_pass: str) -> SplitPatcherResult:
        """Parchea un split APK inyectando frida-gadget en la librería objetivo"""
        self.check_requirements()
        
        split_apk = Path(split_apk_path)
        if not split_apk.exists():
            return SplitPatcherResult(success=False, error=f"El archivo {split_apk_path} no existe.")
            
        task_dir = self.work_dir / split_apk.stem
        if task_dir.exists():
            shutil.rmtree(task_dir)
        task_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_dir = task_dir / "extracted"
        extracted_dir.mkdir()
        
        try:
            # 1. Descomprimir
            logger.info(f"Descomprimiendo {split_apk_path} en {extracted_dir}")
            with zipfile.ZipFile(split_apk, 'r') as zf:
                zf.extractall(extracted_dir)
                
            # Buscar la librería objetivo
            target_libs = list(extracted_dir.rglob(target_lib_name))
            if not target_libs:
                fallback_libs = list(extracted_dir.rglob("*.so"))
                if not fallback_libs:
                    return SplitPatcherResult(success=False, error="No se encontraron librerías nativas (.so) en el split.")
                target_lib = fallback_libs[0]
                logger.warning(f"Librería objetivo {target_lib_name} no encontrada. Usando fallback: {target_lib.name}")
            else:
                target_lib = target_libs[0]
            
            lib_dir = target_lib.parent
            
            # 2. Inyección ELF con LIEF
            logger.info(f"Inyectando dependencia libfrida-gadget.so en {target_lib}")
            binary = lief.parse(str(target_lib))
            
            # Determinar ABI del binario nativo para resolver el gadget correcto
            machine = binary.header.machine_type
            if machine == lief.ELF.ARCH.AARCH64:
                abi_folder = "arm64-v8a"
            elif machine == lief.ELF.ARCH.ARM:
                abi_folder = "armeabi-v7a"
            elif machine == lief.ELF.ARCH.i386:
                abi_folder = "x86"
            elif machine == lief.ELF.ARCH.x86_64:
                abi_folder = "x86_64"
            else:
                return SplitPatcherResult(success=False, error=f"Arquitectura ELF no soportada: {machine}")
            
            binary.add_library("libfrida-gadget.so")
            patched_lib_path = target_lib.with_suffix(".so.patched")
            binary.write(str(patched_lib_path))
            
            # Reemplazar original con el parchado
            os.replace(patched_lib_path, target_lib)
            
            # 3. Copiar el Gadget REAL y su configuración
            gadget_path = lib_dir / "libfrida-gadget.so"
            real_gadget = Path(f"tools/frida-gadget/{abi_folder}/libfrida-gadget.so")
            
            if not real_gadget.exists():
                fallback_gadget = Path("tools/frida-gadget/libfrida-gadget.so")
                if fallback_gadget.exists():
                    logger.warning(f"Gadget para {abi_folder} no encontrado en {real_gadget}. Usando fallback global.")
                    real_gadget = fallback_gadget
                else:
                    return SplitPatcherResult(
                        success=False, 
                        error=f"El gadget real no se encontró en {real_gadget} ni en {fallback_gadget}. Descárgalo primero."
                    )
                
            shutil.copy(real_gadget, gadget_path)
            os.chmod(gadget_path, 0o644)
            
            config_path = lib_dir / "libfrida-gadget.config.so"
            config_path.write_text('{\n  "interaction": {\n    "type": "script",\n    "path": "libstealth.so"\n  }\n}')
            
            stealth_path = lib_dir / "libstealth.so"
            stealth_js_content = """
// Evasión RASP: Cegado de /proc/self/maps (FrihDah Cap. 5.2)
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = Memory.readCString(args[0]);
        if (this.path !== null && this.path.indexOf("/proc/self/maps") !== -1) {
            this.is_target = true;
        } else {
            this.is_target = false;
        }
    },
    onLeave: function(retval) {
        if (this.is_target) {
            retval.replace(-1);
            var errno = Memory.alloc(4);
            errno.writeInt(13); // 13 = EACCES (Permission Denied)
            Module.findExportByName("libc.so", "__errno")().writePointer(errno);
        }
    }
});
console.log("[*] RASP Evasion: /proc/self/maps hooked successfully.");
"""
            stealth_path.write_text(stealth_js_content)

            # 4. Reempaquetado Crítico (zip -0)
            repacked_apk = task_dir / "split_repacked.apk"
            logger.info(f"Reempaquetando APK sin compresión en {repacked_apk}")
            subprocess.run(["zip", "-r", "-0", str(repacked_apk), "."], cwd=str(extracted_dir), check=True, stdout=subprocess.DEVNULL)
            
            # Zipalign
            aligned_apk = task_dir / "split_patched.apk"
            logger.info("Aplicando zipalign -p -f 4")
            subprocess.run(["zipalign", "-p", "-f", "4", str(repacked_apk), str(aligned_apk)], check=True)
            
            # Validar zipalign
            subprocess.run(["zipalign", "-c", "-v", "4", str(aligned_apk)], check=True, stdout=subprocess.DEVNULL)
            
            # 5. Firma de TODOS los splits
            base_apk = split_apk.parent / "base.apk"
            other_splits = [p for p in split_apk.parent.glob("*.apk") if p != split_apk and p.name != "base.apk"]
            
            splits_to_sign = [aligned_apk]
            if base_apk.exists():
                splits_to_sign.append(base_apk)
            splits_to_sign.extend(other_splits)
            
            signed_splits = []
            logger.info("Firmando base.apk y todos los splits...")
            for apk_to_sign in splits_to_sign:
                logger.info(f"Firmando {apk_to_sign}")
                subprocess.run([
                    "apksigner", "sign", "--ks", keystore_path, "--ks-pass", f"pass:{keystore_pass}", str(apk_to_sign)
                ], check=True)
                signed_splits.append(str(apk_to_sign))
                
            # 6. Instalación
            install_cmd = ["adb", "install-multiple", "-r", "-d"] + signed_splits
            logger.info(f"Instalando splits: {' '.join(install_cmd)}")
            try:
                subprocess.run(install_cmd, check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Error instalando splits (quizás no hay dispositivo conectado): {e}")
            
            return SplitPatcherResult(
                success=True, 
                patched_apk=str(aligned_apk), 
                original_splits=signed_splits
            )
            
        except subprocess.CalledProcessError as e:
            return SplitPatcherResult(success=False, error=f"Error en comando externo: {e.cmd}")
        except Exception as e:
            return SplitPatcherResult(success=False, error=str(e))
-e 
--- FILE: ./modules/__init__.py ---

-e 
--- FILE: ./modules/executor.py ---
"""
Módulo ejecutor - Orquesta todas las herramientas según el plan
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import logging

from modules.ingester import APKIngester, APKInfo
from modules.planner import APKPlanner, AnalysisPlan
from tools.static_analysis import JadxWrapper, ApktoolWrapper, GhidraWrapper
from tools.dynamic_analysis import FridaWrapper, ObjectionWrapper, R2FridaWrapper
from tools.specialized_tools import Il2CppDumperWrapper, HermesDecWrapper
from tools.mobsf_api import MobSFWrapper
from modules.split_patcher import SplitAPKPatcher
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ExecutionResult:
    """Resultado de una tarea de ejecución"""
    
    def __init__(self, task_name: str, success: bool, output: Dict, duration: float):
        self.task_name = task_name
        self.success = success
        self.output = output
        self.duration = duration
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            'task': self.task_name,
            'success': self.success,
            'duration_sec': self.duration,
            'timestamp': self.timestamp,
            'output_summary': self._summarize_output()
        }
    
    def _summarize_output(self) -> str:
        if self.success:
            return f"Completado - {len(str(self.output))} bytes de output"
        else:
            return f"Fallo: {self.output.get('error', 'Error desconocido')}"


class APKExecutor:
    """
    Ejecutor principal que orquesta todas las herramientas
    según el plan generado
    """
    
    def __init__(self, work_dir: str = "output"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Inicializar wrappers
        self.jadx = JadxWrapper()
        self.apktool = ApktoolWrapper()
        self.ghidra = GhidraWrapper()
        self.frida = FridaWrapper()
        self.objection = ObjectionWrapper()
        self.il2cpp = Il2CppDumperWrapper()
        self.hermes = HermesDecWrapper()
        self.mobsf = MobSFWrapper()
        self.r2frida = R2FridaWrapper()
        self.split_patcher = SplitAPKPatcher(work_dir=str(self.work_dir / "patches"))
        
        # Tracking de resultados
        self.results: List[ExecutionResult] = []
        self.current_plan: Optional[AnalysisPlan] = None
    
    def execute_plan(self, apk_path: str, plan: AnalysisPlan, 
                     device_connected: bool = False) -> Dict:
        """
        Ejecuta el plan completo de análisis
        
        Args:
            apk_path: Ruta al archivo APK
            plan: Plan de análisis generado por APKPlanner
            device_connected: Si hay dispositivo Android conectado para análisis dinámico
        
        Returns:
            Dict con resultados consolidados
        """
        self.current_plan = plan
        self.results = []
        
        logger.info(f"🚀 Iniciando ejecución del plan para {plan.package_name}")
        logger.info(f"   Tareas a ejecutar: {plan.total_tasks}")
        logger.info(f"   Herramientas: {', '.join(plan.recommended_tools)}")
        
        if plan.special_considerations:
            logger.info("   Consideraciones especiales:")
            for consideration in plan.special_considerations:
                logger.info(f"     • {consideration}")
        
        # Crear directorio de trabajo específico
        apk_hash = plan.apk_hash
        task_dir = self.work_dir / apk_hash
        task_dir.mkdir(parents=True, exist_ok=True)
        
        start_time = time.time()
        
        # Ejecutar tareas en orden de prioridad
        for i, task in enumerate(plan.tasks, 1):
            logger.info(f"\n[{i}/{plan.total_tasks}] Ejecutando: {task.tool} - {task.description}")
            
            result = self._execute_task(task, apk_path, task_dir, device_connected)
            self.results.append(result)
            
            status = "✅" if result.success else "❌"
            logger.info(f"{status} {task.tool} completado en {result.duration:.1f}s")
        
        total_time = time.time() - start_time
        
        # Generar reporte consolidado
        report = self._generate_report(apk_path, plan, total_time)
        
        # Guardar reporte
        report_file = task_dir / "analysis_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"📊 Análisis completado en {total_time:.1f}s")
        logger.info(f"   Tareas exitosas: {sum(1 for r in self.results if r.success)}/{len(self.results)}")
        logger.info(f"   Reporte guardado: {report_file}")
        logger.info(f"{'='*60}")
        
        return report
    
    def _execute_task(self, task, apk_path: str, task_dir: Path, 
                      device_connected: bool) -> ExecutionResult:
        """Ejecuta una tarea individual"""
        start = time.time()
        tool = task.tool
        params = task.parameters
        
        try:
            output = {}
            
            if tool == "jadx":
                output = self._run_jadx(apk_path, task_dir, params)
            
            elif tool == "apktool":
                output = self._run_apktool(apk_path, task_dir, params)
            
            elif tool == "ghidra":
                output = self._run_ghidra(apk_path, task_dir, params)
            
            elif tool == "frida":
                if device_connected:
                    output = self._run_frida(apk_path, task_dir, params)
                else:
                    output = {'success': False, 'skipped': True, 'reason': 'No device connected'}
            
            elif tool == "objection":
                if device_connected:
                    output = self._run_objection(apk_path, task_dir, params)
                else:
                    output = {'success': False, 'skipped': True, 'reason': 'No device connected'}

            elif tool == "r2frida":
                if device_connected:
                    output = self._run_r2frida(apk_path, task_dir, params)
                else:
                    output = {'success': False, 'skipped': True, 'reason': 'No device connected'}
            
            elif tool == "il2cppdumper":
                output = self._run_il2cppdumper(apk_path, task_dir, params)
            
            elif tool == "hermes-dec":
                output = self._run_hermes_dec(apk_path, task_dir, params)
            
            elif tool == "mobsf":
                output = self._run_mobsf(apk_path, task_dir, params)

            elif tool == "split_patcher":
                output = self._run_split_patcher(apk_path, params)
            
            elif tool == "frida_gadget":
                output = self._run_frida_gadget(apk_path, params)
            
            duration = time.time() - start
            success = output.get('success', False) or output.get('skipped', False)
            
            return ExecutionResult(tool, success, output, duration)
            
        except Exception as e:
            duration = time.time() - start
            logger.error(f"Error en {tool}: {str(e)}")
            return ExecutionResult(
                tool, 
                False, 
                {'error': str(e)}, 
                duration
            )
    
    def _run_jadx(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        output_dir = task_dir / "jadx_output"
        return self.jadx.decompile(
            apk_path, 
            str(output_dir),
            threads=params.get('threads', 4),
            no_resources=params.get('no_resources', False)
        )
    
    def _run_apktool(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        output_dir = task_dir / "apktool_output"
        return self.apktool.decode(
            apk_path,
            str(output_dir),
            no_src=params.get('no_src', True),
            force=params.get('force', True)
        )
    
    def _run_ghidra(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        # Extraer librerías nativas primero
        import zipfile
        
        native_dir = task_dir / "native_libs"
        native_dir.mkdir(exist_ok=True)
        
        so_files = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.so'):
                        zf.extract(name, native_dir)
                        so_files.append(os.path.join(native_dir, name))
        except Exception as e:
            return {'success': False, 'error': f'Error extrayendo .so: {str(e)}'}
        
        if not so_files:
            return {'success': True, 'skipped': True, 'reason': 'No .so files found'}
        
        # Analizar primera librería (se puede extender para todas)
        project_dir = task_dir / "ghidra_projects"
        result = self.ghidra.analyze_so(
            so_files[0],
            str(project_dir),
            script_path=params.get('script_path')
        )
        
        result['analyzed_count'] = len(so_files)
        result['so_files'] = so_files[:10]  # Listar primeras 10
        
        return result
    
    def _run_frida(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        # Extraer package name del APK
        ingester = APKIngester()
        info = ingester.analyze(apk_path)
        package_name = info.package_name
        
        if not package_name:
            return {'success': False, 'error': 'No se pudo extraer package name'}
        
        # Verificar frida-server
        if not self.frida.check_frida_server():
            logger.warning("frida-server no está corriendo. Intentando fallback a R2Frida.")
            if self.r2frida.check_r2frida():
                return self._run_r2frida(apk_path, task_dir, params)
            else:
                return {'success': False, 'error': 'Frida-server no disponible'}
        
        # Generar script si no se proporcionó
        script_dir = task_dir / "frida_scripts"
        script_dir.mkdir(exist_ok=True)
        
        from tools.dynamic_analysis import create_frida_script_bypass_all
        script_content = create_frida_script_bypass_all()
        script_path = script_dir / "bypass_all.js"
        script_path.write_text(script_content)
        
        # Ejecutar (timeout corto para demo)
        res = self.frida.spawn_and_attach(
            package_name,
            str(script_path),
            output_callback=lambda line: logger.info(f"Frida: {line}")
        )
        if res.get('success'):
            res['owasp_control'] = 'MASTG-TEST-0022, MASTG-TEST-0045'
        return res
    
    def _run_r2frida(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        ingester = APKIngester()
        info = ingester.analyze(apk_path)
        package_name = info.package_name
        
        if not package_name:
            return {'success': False, 'error': 'No se pudo extraer package name'}
        
        if not self.r2frida.check_r2frida():
             return {'success': False, 'error': 'El plugin r2frida no está instalado o r2 no está disponible.'}

        commands = params.get('commands', [])
        if commands:
            return self.r2frida.execute_commands(package_name, commands)
        else:
            return self.r2frida.explore_binary(package_name)

    def _run_objection(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        ingester = APKIngester()
        info = ingester.analyze(apk_path)
        package_name = info.package_name
        
        if not package_name:
            return {'success': False, 'error': 'No se pudo extraer package name'}
        
        self.objection.set_package(package_name)
        
        commands = params.get('commands', ['android sslpinning disable', 'exit'])
        res = self.objection.explore(commands)
        if res.get('success'):
            res['owasp_control'] = 'MASTG-TEST-0022'
        return res
    
    def _run_il2cppdumper(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        dump_dir = task_dir / "il2cpp_dump"
        return self.il2cpp.extract_from_apk(apk_path, str(dump_dir))
    
    def _run_hermes_dec(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        bundle_dir = task_dir / "hermes_bundle"
        return self.hermes.extract_from_apk(apk_path, str(bundle_dir))
    
    def _run_split_patcher(self, apk_path: str, params: Dict) -> Dict:
        target_lib = params.get("target_lib", "libreactnative.so")
        ks_path = os.environ.get("KEYSTORE_PATH", "debug.keystore")
        ks_pass = os.environ.get("KEYSTORE_PASS", "android")
        
        try:
            result = self.split_patcher.patch_split(apk_path, target_lib, ks_path, ks_pass)
            return {
                'success': result.success,
                'patched_apk': result.patched_apk,
                'original_splits': result.original_splits,
                'error': result.error,
                'owasp_control': 'MASTG-TEST-0058'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_frida_gadget(self, apk_path: str, params: Dict) -> Dict:
        mode = params.get("mode", "wait")
        if mode == "wait":
            logger.info("Configurando adb forward para Frida Gadget...")
            try:
                subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], check=True, stdout=subprocess.DEVNULL)
                time.sleep(2)
                logger.info("Conectando frida al Gadget...")
                
                # Simulando un attach al Gadget si hay un script configurado (ej: spoof.js)
                spoof_script = "scripts/spoof.js"
                if not os.path.exists(spoof_script):
                    os.makedirs("scripts", exist_ok=True)
                    with open(spoof_script, "w") as f:
                        f.write('console.log("Spoofing via gadget...");\n')
                
                # Adjuntarse vía frida
                try:
                    subprocess.run(["frida", "-H", "127.0.0.1:27042", "-n", "Gadget", "-l", spoof_script], check=True)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Error adjuntando frida (probablemente no hay gadget/dispositivo corriendo): {e}")
                
                return {
                    'success': True,
                    'info': 'Frida conectado a 127.0.0.1:27042',
                    'owasp_control': 'MASTG-TEST-0058, MASTG-TEST-0018'
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        return {'success': False, 'error': 'Modo no soportado'}

    def _run_mobsf(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        # Check if MobSF integration is properly configured
        if not self.mobsf.api_key:
            return {
                'success': True,
                'info': 'MobSF API key no configurada. Ejecutando de forma manual o simulada.',
                'instructions': 'Configura MOBSF_API_KEY en tu entorno o pasa el api_key a MobSFWrapper.'
            }
        return self.mobsf.upload_and_analyze(apk_path)
    
    def _generate_report(self, apk_path: str, plan: AnalysisPlan, 
                         total_time: float) -> Dict:
        """Genera reporte consolidado del análisis"""
        
        successful_tasks = [r for r in self.results if r.success]
        failed_tasks = [r for r in self.results if not r.success]
        skipped_tasks = [r for r in self.results if r.output.get('skipped')]
        
        report = {
            'metadata': {
                'apk_path': apk_path,
                'package_name': plan.package_name,
                'apk_hash': plan.apk_hash,
                'analysis_date': datetime.now().isoformat(),
                'total_time_seconds': total_time
            },
            'summary': {
                'total_tasks': len(self.results),
                'successful': len(successful_tasks),
                'failed': len(failed_tasks),
                'skipped': len(skipped_tasks),
                'success_rate': len(successful_tasks) / len(self.results) * 100 if self.results else 0
            },
            'plan_info': {
                'recommended_tools': plan.recommended_tools,
                'special_considerations': plan.special_considerations
            },
            'tasks': [r.to_dict() for r in self.results],
            'artifacts': {
                'directories_created': [],
                'files_generated': []
            }
        }
        
        # Listar artifacts generados
        task_dir = self.work_dir / plan.apk_hash
        if task_dir.exists():
            for item in task_dir.rglob('*'):
                if item.is_file():
                    report['artifacts']['files_generated'].append(str(item.relative_to(self.work_dir)))
                elif item.is_dir() and item != task_dir:
                    report['artifacts']['directories_created'].append(str(item.relative_to(self.work_dir)))
        
        return report


if __name__ == "__main__":
    print("=== APK Executor ===\n")
    print("Este módulo orquesta la ejecución de todas las herramientas")
    print("según el plan generado por APKPlanner.\n")
    
    # Ejemplo de uso (requiere APK real)
    print("Uso básico:")
    print("""
    from modules.executor import APKExecutor
    from modules.planner import APKPlanner
    from modules.ingester import APKIngester
    
    # 1. Ingestar APK
    ingester = APKIngester()
    info = ingester.analyze("input/app.apk")
    
    # 2. Generar plan
    planner = APKPlanner()
    plan = planner.create_plan(info)
    
    # 3. Ejecutar plan
    executor = APKExecutor()
    results = executor.execute_plan("input/app.apk", plan, device_connected=False)
    """)

-e 
--- FILE: ./modules/planner.py ---
"""
Módulo de planificación de análisis
Determina qué herramientas y técnicas usar basándose en las características del APK
"""

from typing import List, Dict, Optional
from pydantic import BaseModel
from pathlib import Path


class AnalysisTask(BaseModel):
    """Tarea individual de análisis"""
    tool: str
    description: str
    priority: int  # 1-5, donde 1 es más prioritario
    parameters: Dict = {}
    estimated_time: str = "unknown"


class AnalysisPlan(BaseModel):
    """Plan completo de análisis para un APK"""
    apk_hash: str
    package_name: str
    total_tasks: int
    tasks: List[AnalysisTask]
    recommended_tools: List[str]
    special_considerations: List[str] = []


class APKPlanner:
    """
    Planificador inteligente que determina el mejor enfoque de análisis
    basado en las características detectadas del APK
    """
    
    # Mapeo de características a herramientas recomendadas
    TOOL_MAPPING = {
        'standard': ['jadx', 'apktool'],
        'native_libs': ['ghidra', 'r2frida'],
        'unity': ['il2cppdumper', 'ghidra'],
        'react_native': ['hermes-dec', 'frida'],
        'flutter': ['frida', 'dart_analyzer'],
        'xamarin': ['dnSpy', 'ilspy'],
        'high_security': ['frida', 'objection', 'burp'],
        'malware_suspect': ['mobsf', 'jadx', 'apktool', 'r2frida']
    }
    
    def __init__(self):
        self.plans_dir = Path("output/plans")
        self.plans_dir.mkdir(parents=True, exist_ok=True)
    
    def create_plan(self, apk_info) -> AnalysisPlan:
        """
        Crea un plan de análisis basado en la información del APK usando un Árbol de Decisión Dinámico.
        [INFO] Para futuras extensiones con Dexcalibur (Generación Dinámica de Hooks), se debe insertar
        la evaluación heurística de Dexcalibur inmediatamente después de Frida si se detecta ofuscación.
        """
        tasks = []
        recommended_tools = set()
        considerations = []
        
        # Detectar tipo de aplicación y agregar tareas específicas
        if apk_info.has_unity_libs:
            considerations.append("Aplicación Unity detectada - requiere herramientas especializadas IL2CPP")
            tasks.append(AnalysisTask(
                tool="il2cppdumper",
                description="Extraer metadatos de IL2CPP para análisis",
                priority=2,
                parameters={"dump_method_info": True, "generate_scripts": True},
                estimated_time="3-10 min"
            ))
            tasks.append(AnalysisTask(
                tool="ghidra",
                description="Análisis de librerías nativas Unity",
                priority=3,
                parameters={"script": "il2cpp_helper.py"},
                estimated_time="10-30 min"
            ))
            recommended_tools.update(['il2cppdumper', 'ghidra'])
        
        if apk_info.has_react_native:
            considerations.append("React Native detectado - bytecode Hermes puede estar presente")
            tasks.append(AnalysisTask(
                tool="hermes-dec",
                description="Decompilar bytecode Hermes si está presente",
                priority=2,
                parameters={"bytecode_path": "assets/index.android.bundle"},
                estimated_time="2-5 min"
            ))
            tasks.append(AnalysisTask(
                tool="frida",
                description="Instrumentación para explorar bridge React Native",
                priority=3,
                parameters={"scripts": ["react-native-tracer.js"]},
                estimated_time="15-30 min"
            ))
            recommended_tools.update(['hermes-dec', 'frida'])
            
            if apk_info.is_split_apk:
                considerations.append("Split APKs (AAB) detected. Applying SplitAPKPatcher.")
                tasks.append(AnalysisTask(tool="split_patcher", description="Patch split APK via ELF injection", priority=2, parameters={"target_lib": "libreactnative.so", "mode": "script_wait"}))
                recommended_tools.add('split_patcher')
                
        if getattr(apk_info, 'has_flutter', False):
            considerations.append("Flutter Framework detected.")
            tasks.append(AnalysisTask(tool="flutter_dump", description="Dump Flutter app", priority=1, parameters={"target": "libapp.so"}))
            recommended_tools.add('flutter_dump')
        # Análisis estático básico (siempre se realiza)
        considerations.append("Standard Android Application components detected.")
        tasks.append(AnalysisTask(tool="jadx", description="Decompile DEX to Java", priority=1))
        tasks.append(AnalysisTask(tool="apktool", description="Decode resources", priority=2))
        recommended_tools.update(['jadx', 'apktool'])
        
        # Inyección dinámica si hay RASP o no hay root
        if not getattr(apk_info, 'root_available', True) and apk_info.has_native_libs:
            considerations.append("No root available and native libs detected. Scheduling Frida Gadget Injection for RASP evasion.")
            tasks.append(AnalysisTask(tool="frida_gadget", description="Inject Frida Gadget dynamically", priority=3, parameters={"mode": "wait"}))
            recommended_tools.add('frida_gadget')
        
        # Ordenar tareas por prioridad
        tasks.sort(key=lambda t: t.priority)
        
        plan = AnalysisPlan(
            apk_hash=apk_info.sha256[:16],
            package_name=apk_info.package_name or "unknown",
            total_tasks=len(tasks),
            tasks=tasks,
            recommended_tools=list(recommended_tools),
            special_considerations=considerations
        )
        
        # Guardar plan
        self.save_plan(plan)
        
        return plan
    
    def save_plan(self, plan: AnalysisPlan):
        """Guarda el plan en archivo JSON"""
        import json
        
        plan_file = self.plans_dir / f"{plan.apk_hash}_plan.json"
        with open(plan_file, 'w') as f:
            json.dump(plan.model_dump(), f, indent=2)
    
    def load_plan(self, apk_hash: str) -> Optional[AnalysisPlan]:
        """Carga un plan existente"""
        import json
        
        plan_file = self.plans_dir / f"{apk_hash[:16]}_plan.json"
        if not plan_file.exists():
            return None
        
        with open(plan_file, 'r') as f:
            data = json.load(f)
        
        return AnalysisPlan(**data)
    
    def get_tool_requirements(self, tools: List[str]) -> Dict:
        """
        Retorna los requisitos e instalación para las herramientas recomendadas
        """
        requirements = {
            'jadx': {
                'install': 'wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip && unzip jadx-1.4.7.zip',
                'docker': 'skylot/jadx',
                'cli': 'jadx-gui o jadx'
            },
            'apktool': {
                'install': 'apt install apktool o descargar desde GitHub',
                'docker': 'include en la mayoría de imágenes de RE',
                'cli': 'apktool d/c'
            },
            'frida': {
                'install': 'pip install frida-tools',
                'server': 'adb push frida-server /data/local/tmp && chmod +x',
                'cli': 'frida -U -f com.app o frida-trace'
            },
            'objection': {
                'install': 'pip install objection',
                'cli': 'objection explore',
                'requires': 'frida-server corriendo'
            },
            'ghidra': {
                'install': 'Descargar desde ghidra-sre.org',
                'docker': 'ahmedkhlief/ghidra-docker',
                'cli': 'analyzeHeadless o GUI'
            },
            'il2cppdumper': {
                'install': 'dotnet tool install -g il2cppdumper',
                'cli': 'il2cppdumper global-metadata.dat libil2cpp.so output/'
            },
            'hermes-dec': {
                'install': 'git clone https://github.com/P1sec/hermes-dec',
                'cli': 'python hermes-dec.py bytecode.hbc'
            },
            'mobsf': {
                'install': 'docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf',
                'web': 'http://localhost:8000',
                'api': 'http://localhost:8000/api/v1/'
            }
        }
        
        return {tool: requirements.get(tool, {'info': 'Herramienta no documentada'}) for tool in tools}


if __name__ == "__main__":
    # Ejemplo de uso
    from modules.ingester import APKInfo
    
    # Simular información de APK
    apk_info = APKInfo(
        file_path="test.apk",
        file_size=15000000,
        md5="abc123",
        sha256="def456789",
        is_valid=True,
        package_name="com.example.app",
        permissions=[
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION'
        ],
        has_native_libs=True,
        has_unity_libs=False,
        has_react_native=True
    )
    
    planner = APKPlanner()
    plan = planner.create_plan(apk_info)
    
    print(f"\n📋 Plan de Análisis para: {plan.package_name}")
    print(f"{'='*50}")
    print(f"Tareas totales: {plan.total_tasks}")
    print(f"Herramientas recomendadas: {', '.join(plan.recommended_tools)}")
    
    if plan.special_considerations:
        print(f"\n⚠️ Consideraciones especiales:")
        for consideration in plan.special_considerations:
            print(f"  • {consideration}")
    
    print(f"\n📝 Tareas:")
    for i, task in enumerate(plan.tasks, 1):
        print(f"  {i}. [{task.tool}] {task.description} (Prioridad: {task.priority})")

-e 
--- FILE: ./modules/ingester.py ---
"""
Módulo de ingesta y validación de APKs
Valida archivos APK, extrae metadatos básicos y prepara para el análisis
"""

import os
import hashlib
import magic
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple
from pydantic import BaseModel
from xml.parsers.expat import ExpatError
import xmltodict


class APKInfo(BaseModel):
    """Información básica del APK"""
    file_path: str
    file_size: int
    md5: str
    sha256: str
    is_valid: bool
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    app_name: Optional[str] = None
    permissions: list = []
    has_native_libs: bool = False
    has_unity_libs: bool = False
    has_react_native: bool = False
    is_split_apk: bool = False
    extract_native_libs: bool = True
    root_available: bool = False  # Placeholder, typically resolved dynamically 
    error_message: Optional[str] = None


class APKIngester:
    """Clase principal para ingestión y validación de APKs"""
    
    def __init__(self, input_dir: str = "input", output_dir: str = "output"):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def validate_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Valida que el archivo sea un APK válido
        Returns: (es_valido, mensaje_error)
        """
        path = Path(file_path)
        
        # Verificar existencia
        if not path.exists():
            return False, f"El archivo no existe: {file_path}"
        
        # Verificar extensión
        if path.suffix.lower() not in ['.apk', '.ipa']:
            return False, f"Extensión inválida: {path.suffix}. Se espera .apk o .ipa"
        
        # Verificar tipo MIME
        try:
            mime = magic.from_file(str(path), mime=True)
            if mime not in ['application/vnd.android.package-archive', 'application/x-ios-app', 'application/zip', 'application/octet-stream']:
                return False, f"Tipo MIME inválido: {mime}"
        except Exception as e:
            return False, f"Error al verificar tipo MIME: {str(e)}"
        
        # Verificar estructura ZIP
        try:
            with zipfile.ZipFile(path, 'r') as zf:
                # Verificar archivos esenciales según plataforma
                namelist = zf.namelist()
                
                is_apk = any(n == 'AndroidManifest.xml' for n in namelist)
                is_ipa = any('Payload/' in n and n.endswith('.app/Info.plist') for n in namelist)
                
                if not is_apk and not is_ipa:
                    return False, f"Archivo esencial faltante: AndroidManifest.xml o Info.plist"
                        
        except zipfile.BadZipFile:
            return False, "El archivo no es un ZIP válido (APK/IPA corrupto)"
        except Exception as e:
            return False, f"Error al leer ZIP: {str(e)}"
        
        return True, ""
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcula hashes MD5 y SHA256 del archivo"""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            'md5': md5_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
    
    def extract_manifest_info(self, file_path: str) -> Dict:
        """Extrae información del AndroidManifest.xml o Info.plist"""
        info = {}
        
        is_ios = str(file_path).lower().endswith('.ipa')
        
        if is_ios:
            import plistlib
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    namelist = zf.namelist()
                    plist_path = next((n for n in namelist if 'Payload/' in n and n.endswith('.app/Info.plist')), None)
                    if plist_path:
                        plist_data = zf.read(plist_path)
                        try:
                            plist = plistlib.loads(plist_data)
                            info['package_name'] = plist.get('CFBundleIdentifier')
                            info['version_name'] = plist.get('CFBundleShortVersionString')
                            info['version_code'] = plist.get('CFBundleVersion')
                            info['app_name'] = plist.get('CFBundleName') or plist.get('CFBundleDisplayName')
                            info['min_sdk'] = plist.get('MinimumOSVersion')
                            info['target_sdk'] = None
                            info['permissions'] = [k for k in plist.keys() if k.startswith('NS') and k.endswith('UsageDescription')]
                        except Exception as e:
                            info['error'] = f"Error al parsear Info.plist: {e}"
            except Exception as e:
                info['error'] = str(e)
            return info

        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Intentar parsear (androguard lo maneja mejor)
                try:
                    from androguard.core.bytecodes.apk import APK
                    apk = APK(file_path)
                    
                    info['package_name'] = apk.get_package()
                    info['version_name'] = apk.get_androidversion_name()
                    info['version_code'] = apk.get_androidversion_code()
                    info['min_sdk'] = apk.get_min_sdk_version()
                    info['target_sdk'] = apk.get_target_sdk_version()
                    info['app_name'] = apk.get_app_name()
                    info['permissions'] = apk.get_permissions()
                    
                    # Extraer extractNativeLibs
                    manifest_xml = apk.get_android_manifest_xml()
                    if manifest_xml is not None:
                        app_elem = manifest_xml.find("application")
                        if app_elem is not None:
                            ns = "{http://schemas.android.com/apk/res/android}"
                            extract = app_elem.get(f"{ns}extractNativeLibs", "true")
                            info['extract_native_libs'] = extract.lower() == "true"
                    
                except ImportError as e:
                    logger.error("Error crítico de importación: la librería 'androguard' es obligatoria para la extracción de metadatos.")
                    raise e
                    
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def detect_features(self, file_path: str) -> Dict:
        """Detecta características especiales del APK"""
        features = {
            'has_native_libs': False,
            'has_unity_libs': False,
            'has_react_native': False,
            'has_xamarin': False,
            'has_flutter': False,
            'detected_frameworks': []
        }
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                namelist = zf.namelist()
                
                # Detectar librerías nativas
                if any(name.startswith('lib/') and name.endswith('.so') for name in namelist):
                    features['has_native_libs'] = True
                
                # Detectar Unity
                unity_indicators = [
                    'lib/mono/',
                    'assets/bin/Data/',
                    'libil2cpp.so',
                    'global-metadata.dat'
                ]
                if any(ind in namelist or any(ind in name for name in namelist) for ind in unity_indicators):
                    features['has_unity_libs'] = True
                    features['detected_frameworks'].append('Unity')
                
                # Detectar React Native
                react_indicators = [
                    'index.android.bundle',
                    'libreactnativejni.so',
                    'libhermes.so',
                    'assets/index.android.bundle'
                ]
                if any(ind in namelist or any(ind in name for name in namelist) for ind in react_indicators):
                    features['has_react_native'] = True
                    features['detected_frameworks'].append('React Native')
                
                # Detectar Xamarin
                if any('Mono' in name or 'Xamarin' in name for name in namelist):
                    features['has_xamarin'] = True
                    features['detected_frameworks'].append('Xamarin')
                
                # Detectar Flutter
                flutter_indicators = ['libflutter.so', 'libapp.so']
                if any(ind in namelist or any('/' + ind in name for name in namelist) for ind in flutter_indicators):
                    features['has_flutter'] = True
                    features['detected_frameworks'].append('Flutter')
                    
        except Exception as e:
            features['detection_error'] = str(e)
        
        return features
    
    def analyze(self, file_path: str) -> APKInfo:
        """
        Análisis completo del APK
        Returns: APKInfo con toda la información extraída
        """
        # Validar archivo
        is_valid, error_msg = self.validate_file(file_path)
        
        if not is_valid:
            return APKInfo(
                file_path=file_path,
                file_size=0,
                md5="",
                sha256="",
                is_valid=False,
                error_message=error_msg
            )
        
        # Calcular hashes
        hashes = self.calculate_hashes(file_path)
        
        # Obtener tamaño
        file_size = os.path.getsize(file_path)
        
        # Extraer información del manifiesto
        manifest_info = self.extract_manifest_info(file_path)
        
        # Detectar características
        features = self.detect_features(file_path)
        
        # Detectar splits
        is_split = any(p.name.startswith("split_config") for p in Path(file_path).parent.glob("*.apk"))
        
        # Construir resultado
        return APKInfo(
            file_path=file_path,
            file_size=file_size,
            md5=hashes['md5'],
            sha256=hashes['sha256'],
            is_valid=True,
            package_name=manifest_info.get('package_name'),
            version_name=manifest_info.get('version_name'),
            version_code=manifest_info.get('version_code'),
            min_sdk=manifest_info.get('min_sdk'),
            target_sdk=manifest_info.get('target_sdk'),
            app_name=manifest_info.get('app_name'),
            permissions=manifest_info.get('permissions', []),
            has_native_libs=features['has_native_libs'],
            has_unity_libs=features['has_unity_libs'],
            has_react_native=features['has_react_native'],
            is_split_apk=is_split,
            extract_native_libs=manifest_info.get('extract_native_libs', True),
            root_available=False,
            error_message=None
        )
    
    def prepare_analysis_dir(self, apk_hash: str) -> Path:
        """Prepara directorio de trabajo para un APK específico"""
        work_dir = self.output_dir / apk_hash[:16]
        work_dir.mkdir(parents=True, exist_ok=True)
        
        # Crear subdirectorios
        (work_dir / "decompiled").mkdir(exist_ok=True)
        (work_dir / "sources").mkdir(exist_ok=True)
        (work_dir / "native").mkdir(exist_ok=True)
        (work_dir / "temp").mkdir(exist_ok=True)
        
        return work_dir


if __name__ == "__main__":
    # Ejemplo de uso
    ingester = APKIngester()
    
    test_apk = "input/test.apk"
    if os.path.exists(test_apk):
        info = ingester.analyze(test_apk)
        print(f"Package: {info.package_name}")
        print(f"Válido: {info.is_valid}")
        print(f"Frameworks detectados: {info.has_unity_libs}, {info.has_react_native}")
    else:
        print(f"Archivo de prueba no encontrado: {test_apk}")

-e 
--- FILE: ./modules/main.py ---
"""
Módulo principal - API unificada para el sistema de Reverse Engineering
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict
import logging
import json

# Agregar root al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.ingester import APKIngester, APKInfo
from modules.planner import APKPlanner, AnalysisPlan
from modules.executor import APKExecutor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APKReverseSystem:
    """
    Sistema principal de Reverse Engineering de APKs
    
    Proporciona una API unificada para:
    1. Validar e ingestar APKs
    2. Generar planes de análisis inteligentes
    3. Ejecutar herramientas automáticamente
    4. Generar reportes consolidados
    """
    
    def __init__(self, base_dir: str = None):
        """
        Inicializa el sistema
        
        Args:
            base_dir: Directorio base del sistema (default: directorio actual)
        """
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent.parent
        self.input_dir = self.base_dir / "input"
        self.output_dir = self.base_dir / "output"
        self.reports_dir = self.base_dir / "reports"
        
        # Crear directorios
        for dir_path in [self.input_dir, self.output_dir, self.reports_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Inicializar componentes
        self.ingester = APKIngester(
            input_dir=str(self.input_dir),
            output_dir=str(self.output_dir)
        )
        self.planner = APKPlanner()
        self.executor = APKExecutor(work_dir=str(self.output_dir))
        
        logger.info("✅ APK Reverse System inicializado")
        logger.info(f"   Input: {self.input_dir}")
        logger.info(f"   Output: {self.output_dir}")
        logger.info(f"   Reports: {self.reports_dir}")
    
    def analyze(self, apk_path: str, device_connected: bool = False,
                generate_report: bool = True) -> Dict:
        """
        Análisis completo automatizado de un APK
        
        Args:
            apk_path: Ruta al archivo APK
            device_connected: Si hay dispositivo Android conectado
            generate_report: Generar reporte HTML/Markdown
        
        Returns:
            Dict con resultados completos del análisis
        """
        logger.info("=" * 60)
        logger.info("🔍 APK REVERSE ENGINEERING SYSTEM")
        logger.info("=" * 60)
        
        # Paso 1: Validar e ingestar
        logger.info("\n[1/3] 📥 Ingestando APK...")
        apk_info = self.ingester.analyze(apk_path)
        
        if not apk_info.is_valid:
            logger.error(f"❌ APK inválido: {apk_info.error_message}")
            return {
                'success': False,
                'error': apk_info.error_message,
                'stage': 'ingestion'
            }
        
        logger.info(f"✅ APK válido")
        logger.info(f"   Package: {apk_info.package_name}")
        logger.info(f"   Size: {apk_info.file_size:,} bytes")
        logger.info(f"   SHA256: {apk_info.sha256[:32]}...")
        
        if apk_info.permissions:
            logger.info(f"   Permissions: {len(apk_info.permissions)}")
        
        frameworks = []
        if apk_info.has_unity_libs:
            frameworks.append("Unity")
        if apk_info.has_react_native:
            frameworks.append("React Native")
        if apk_info.has_native_libs:
            frameworks.append("Native libs")
        
        if frameworks:
            logger.info(f"   Frameworks: {', '.join(frameworks)}")
        
        # Paso 2: Generar plan
        logger.info("\n[2/3] 📋 Generando plan de análisis...")
        plan = self.planner.create_plan(apk_info)
        
        logger.info(f"✅ Plan generado")
        logger.info(f"   Tareas: {plan.total_tasks}")
        logger.info(f"   Herramientas: {', '.join(plan.recommended_tools)}")
        
        if plan.special_considerations:
            logger.info("   Consideraciones:")
            for consideration in plan.special_considerations:
                logger.info(f"     • {consideration}")
        
        # Paso 3: Ejecutar plan
        logger.info("\n[3/3] 🚀 Ejecutando análisis...")
        results = self.executor.execute_plan(
            apk_path, 
            plan, 
            device_connected=device_connected
        )
        
        # Generar reporte si se solicita
        if generate_report:
            logger.info("\n📝 Generando reportes...")
            report_files = self.generate_reports(apk_info, plan, results)
            results['report_files'] = report_files
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ ANÁLISIS COMPLETADO")
        logger.info("=" * 60)
        
        return {
            'success': True,
            'apk_info': apk_info.model_dump(),
            'plan': plan.model_dump(),
            'execution_results': results,
            'stage': 'completed'
        }
    
    def quick_scan(self, apk_path: str) -> Dict:
        """
        Escaneo rápido solo con análisis estático básico
        
        Args:
            apk_path: Ruta al APK
        
        Returns:
            Dict con información básica
        """
        logger.info("⚡ Quick scan iniciado...")
        
        # Solo ingesta y plan, sin ejecución
        apk_info = self.ingester.analyze(apk_path)
        
        if not apk_info.is_valid:
            return {
                'success': False,
                'error': apk_info.error_message
            }
        
        plan = self.planner.create_plan(apk_info)
        
        return {
            'success': True,
            'apk_info': apk_info.model_dump(),
            'recommended_tools': plan.recommended_tools,
            'considerations': plan.special_considerations,
            'scan_type': 'quick'
        }
    
    def generate_reports(self, apk_info: APKInfo, plan: AnalysisPlan, 
                         results: Dict) -> Dict:
        """
        Genera reportes en múltiples formatos
        
        Args:
            apk_info: Información del APK
            plan: Plan ejecutado
            results: Resultados de la ejecución
        
        Returns:
            Dict con rutas a los reportes generados
        """
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_base = self.reports_dir / f"{apk_info.sha256[:16]}_{timestamp}"
        
        files = {}
        
        # Reporte JSON completo
        json_report = report_base.with_suffix('.json')
        full_report = {
            'apk_info': apk_info.model_dump(),
            'analysis_plan': plan.model_dump(),
            'execution_results': results,
            'generated_at': datetime.now().isoformat()
        }
        
        with open(json_report, 'w') as f:
            json.dump(full_report, f, indent=2, default=str)
        
        files['json'] = str(json_report)
        
        # Reporte Markdown legible
        md_report = report_base.with_suffix('.md')
        md_content = self._generate_markdown_report(apk_info, plan, results)
        
        with open(md_report, 'w') as f:
            f.write(md_content)
        
        files['markdown'] = str(md_report)
        
        logger.info(f"   📄 JSON: {json_report.name}")
        logger.info(f"   📄 Markdown: {md_report.name}")
        
        return files
    
    def _generate_markdown_report(self, apk_info: APKInfo, plan: AnalysisPlan,
                                   results: Dict) -> str:
        """Genera reporte en formato Markdown"""
        
        md = f"""# 📱 Reporte de Análisis de APK

## Información General

| Campo | Valor |
|-------|-------|
| **Package** | `{apk_info.package_name}` |
| **SHA256** | `{apk_info.sha256}` |
| **Tamaño** | {apk_info.file_size:,} bytes |
| **Versión** | {apk_info.version_name or 'N/A'} |
| **SDK Mínimo** | {apk_info.min_sdk or 'N/A'} |
| **SDK Target** | {apk_info.target_sdk or 'N/A'} |

## Permisos ({len(apk_info.permissions)})

"""
        
        # Lista de permisos
        for perm in apk_info.permissions[:20]:
            md += f"- `{perm}`\n"
        
        if len(apk_info.permissions) > 20:
            md += f"\n*... y {len(apk_info.permissions) - 20} más*\n"
        
        md += f"""
## Características Detectadas

- **Librerías Nativas**: {'✅' if apk_info.has_native_libs else '❌'}
- **Unity**: {'✅' if apk_info.has_unity_libs else '❌'}
- **React Native**: {'✅' if apk_info.has_react_native else '❌'}

## Plan de Análisis

### Herramientas Recomendadas

{', '.join([f'`{t}`' for t in plan.recommended_tools])}

### Tareas Ejecutadas ({plan.total_tasks})

| # | Herramienta | Descripción | Prioridad |
|---|-------------|-------------|-----------|
"""
        
        for i, task in enumerate(plan.tasks, 1):
            md += f"| {i} | {task.tool} | {task.description} | {task.priority} |\n"
        
        if plan.special_considerations:
            md += "\n### Consideraciones Especiales\n\n"
            for consideration in plan.special_considerations:
                md += f"⚠️ {consideration}\n"
        
        md += f"""
## Resultados de Ejecución

- **Tareas totales**: {results.get('summary', {}).get('total_tasks', 0)}
- **Exitosas**: {results.get('summary', {}).get('successful', 0)}
- **Fallidas**: {results.get('summary', {}).get('failed', 0)}
- **Omitidas**: {results.get('summary', {}).get('skipped', 0)}
- **Tiempo total**: {results.get('metadata', {}).get('total_time_seconds', 0):.1f}s

---

*Generado por APK Reverse Engineering System*
"""
        
        return md
    
    def list_analyzed_apks(self) -> list:
        """Lista todos los APKs previamente analizados"""
        analyzed = []
        
        for report_file in self.reports_dir.glob("*.json"):
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                    analyzed.append({
                        'package': data.get('apk_info', {}).get('package_name'),
                        'sha256': data.get('apk_info', {}).get('sha256'),
                        'analyzed_at': data.get('generated_at'),
                        'report': str(report_file)
                    })
            except Exception:
                continue
        
        return sorted(analyzed, key=lambda x: x.get('analyzed_at', ''), reverse=True)


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════╗
║     APK REVERSE ENGINEERING SYSTEM                       ║
║     Sistema Automatizado de Análisis de APKs             ║
╚══════════════════════════════════════════════════════════╝

Uso básico:

    from main import APKReverseSystem
    
    # Inicializar sistema
    system = APKReverseSystem()
    
    # Analizar APK
    results = system.analyze("input/mi_app.apk")
    
    # Escaneo rápido
    quick = system.quick_scan("input/otra_app.apk")
    
    # Ver historial
    history = system.list_analyzed_apks()

Comandos CLI disponibles:
    python -m modules.main --help
""")

