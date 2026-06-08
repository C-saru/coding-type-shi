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
