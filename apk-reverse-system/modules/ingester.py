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

                except ImportError:
                    # Fallback básico sin androguard
                    pass
                    
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
