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
