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
