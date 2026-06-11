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
