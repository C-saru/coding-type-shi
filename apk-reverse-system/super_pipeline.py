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
