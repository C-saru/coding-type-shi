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
                # Fallback al primer .so que encontremos en lib/
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
            binary.add_library("libfrida-gadget.so")
            patched_lib_path = target_lib.with_suffix(".so.patched")
            binary.write(str(patched_lib_path))

            # Reemplazar original con el parchado
            os.replace(patched_lib_path, target_lib)

            # Mock del gadget y config. En un caso real, el gadget se debe copiar de una fuente válida.
            gadget_path = lib_dir / "libfrida-gadget.so"
            gadget_path.touch() # TODO: copy real frida-gadget

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
            retval.replace(-1); // Forzar error de archivo no encontrado
            var errno = Memory.alloc(4);
            errno.writeInt(13); // 13 = EACCES (Permission Denied)
            Module.findExportByName("libc.so", "__errno")().writePointer(errno);
        }
    }
});
console.log("[*] RASP Evasion: /proc/self/maps hooked successfully.");
"""
            stealth_path.write_text(stealth_js_content)

            # 3. Reempaquetado Crítico (zip -0)
            repacked_apk = task_dir / "split_repacked.apk"
            logger.info(f"Reempaquetando APK sin compresión en {repacked_apk}")
            subprocess.run(["zip", "-r", "-0", str(repacked_apk), "."], cwd=str(extracted_dir), check=True, stdout=subprocess.DEVNULL)

            # Zipalign
            aligned_apk = task_dir / "split_patched.apk"
            logger.info("Aplicando zipalign -p -f 4")
            subprocess.run(["zipalign", "-p", "-f", "4", str(repacked_apk), str(aligned_apk)], check=True)

            # Validar zipalign
            subprocess.run(["zipalign", "-c", "-v", "4", str(aligned_apk)], check=True, stdout=subprocess.DEVNULL)

            # 4. Firma de TODOS los splits
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

            # 5. Instalación
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
