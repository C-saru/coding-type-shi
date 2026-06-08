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
from tools.dynamic_analysis import FridaWrapper, ObjectionWrapper
from tools.specialized_tools import Il2CppDumperWrapper, HermesDecWrapper

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
            
            elif tool == "il2cppdumper":
                output = self._run_il2cppdumper(apk_path, task_dir, params)
            
            elif tool == "hermes-dec":
                output = self._run_hermes_dec(apk_path, task_dir, params)
            
            elif tool == "mobsf":
                output = {'success': True, 'info': 'MobSF requiere ejecución via Docker/API', 
                         'instructions': 'docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf'}
            
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
            logger.warning("frida-server no está corriendo, intentando iniciar...")
            self.frida.start_frida_server()
        
        # Generar script si no se proporcionó
        script_dir = task_dir / "frida_scripts"
        script_dir.mkdir(exist_ok=True)
        
        from tools.dynamic_analysis import create_frida_script_bypass_all
        script_content = create_frida_script_bypass_all()
        script_path = script_dir / "bypass_all.js"
        script_path.write_text(script_content)
        
        # Ejecutar (timeout corto para demo)
        return self.frida.spawn_and_attach(
            package_name,
            str(script_path),
            output_callback=lambda line: logger.info(f"Frida: {line}")
        )
    
    def _run_objection(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        ingester = APKIngester()
        info = ingester.analyze(apk_path)
        package_name = info.package_name
        
        if not package_name:
            return {'success': False, 'error': 'No se pudo extraer package name'}
        
        self.objection.set_package(package_name)
        
        commands = params.get('commands', ['android sslpinning disable', 'exit'])
        return self.objection.explore(commands)
    
    def _run_il2cppdumper(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        dump_dir = task_dir / "il2cpp_dump"
        return self.il2cpp.extract_from_apk(apk_path, str(dump_dir))
    
    def _run_hermes_dec(self, apk_path: str, task_dir: Path, params: Dict) -> Dict:
        bundle_dir = task_dir / "hermes_bundle"
        return self.hermes.extract_from_apk(apk_path, str(bundle_dir))
    
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
