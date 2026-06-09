import sys
import argparse
import logging
from pathlib import Path

from modules.ingester import APKIngester
from modules.planner import APKPlanner
from modules.executor import APKExecutor
from modules.split_patcher import SplitAPKPatcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SuperPipeline")

def main():
    parser = argparse.ArgumentParser(description="Super Pipeline for Advanced APK Reverse Engineering")
    parser.add_argument("apk_path", help="Path to the primary APK or Base APK of a split installation")
    args = parser.parse_args()

    apk_path = args.apk_path
    if not Path(apk_path).exists():
        logger.error(f"Error: {apk_path} does not exist.")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("🚀 INICIANDO SUPER PIPELINE DE INGENIERÍA INVERSA")
    logger.info("=" * 60)

    # 1. Ingester
    logger.info("\n[1/4] 📥 Ejecutando Ingester...")
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
