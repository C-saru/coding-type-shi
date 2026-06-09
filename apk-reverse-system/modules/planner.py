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
        Crea un plan de análisis basado en la información del APK
        """
        tasks = []
        recommended_tools = set()
        considerations = []
        
        # Análisis estático básico (siempre se realiza)
        tasks.append(AnalysisTask(
            tool="jadx",
            description="Decompilar DEX a código Java legible",
            priority=1,
            parameters={"output_format": "java", "include_resources": False},
            estimated_time="2-5 min"
        ))
        
        tasks.append(AnalysisTask(
            tool="apktool",
            description="Decodear resources.arsc y AndroidManifest.xml",
            priority=1,
            parameters={"no_src": True, "force": True},
            estimated_time="1-3 min"
        ))
        
        recommended_tools.update(['jadx', 'apktool'])
        
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
        
        if apk_info.has_native_libs:
            considerations.append("Librerías nativas (.so) detectadas - análisis binario requerido")
            tasks.append(AnalysisTask(
                tool="ghidra",
                description="Análisis reverse de librerías nativas",
                priority=2,
                parameters={"auto_analyze": True, "find_strings": True},
                estimated_time="15-60 min"
            ))
            tasks.append(AnalysisTask(
                tool="r2frida",
                description="Exploración dinámica en memoria de las librerías cargadas",
                priority=3,
                parameters={"commands": [":il", ":is"]},
                estimated_time="5-10 min"
            ))
            recommended_tools.update(['ghidra', 'r2frida'])
        
        # Verificar permisos sensibles para determinar nivel de seguridad
        high_risk_permissions = [
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS'
        ]
        
        risky_perms = [p for p in apk_info.permissions if p in high_risk_permissions]
        if len(risky_perms) >= 3:
            considerations.append(f"Múltiples permisos sensibles detectados ({len(risky_perms)})")
            tasks.append(AnalysisTask(
                tool="objection",
                description="Exploración runtime y bypass de protecciones",
                priority=2,
                parameters={"explore": True, "ssl_unpin": True},
                estimated_time="10-20 min"
            ))
            recommended_tools.add('objection')
        
        # Detectar posibles protecciones anti-reverse
        protection_indicators = [
            'com.secure',
            'protect',
            'anti.debug',
            'tamper',
            'obfusc'
        ]
        
        has_protections = any(
            ind in cls.lower() 
            for cls in (apk_info.permissions or [])
            for ind in protection_indicators
        )
        
        if has_protections or apk_info.package_name and ('secure' in apk_info.package_name.lower()):
            considerations.append("Posibles protecciones anti-reverse detectadas")
            tasks.append(AnalysisTask(
                tool="frida",
                description="Bypass de detección de root/debug/SSL pinning",
                priority=1,
                parameters={"scripts": ["bypass_all.js"]},
                estimated_time="10-30 min"
            ))
            tasks.append(AnalysisTask(
                tool="objection",
                description="Automatizar bypass de protecciones comunes",
                priority=2,
                parameters={"commands": ["android sslpinning disable", "android root disable"]},
                estimated_time="5-15 min"
            ))
            recommended_tools.update(['frida', 'objection'])
        
        # Análisis de malware potencial (heurística mejorada)
        malware_indicators = 0
        if len(risky_perms) >= 5: malware_indicators += 1
        if apk_info.has_native_libs and len(risky_perms) >= 3: malware_indicators += 1
        if has_protections and len(risky_perms) >= 4: malware_indicators += 1

        suspicious_names = ['payload', 'dropper', 'update', 'install']
        if apk_info.package_name and any(sn in apk_info.package_name.lower() for sn in suspicious_names):
            malware_indicators += 2
        
        if malware_indicators >= 2:
            considerations.append("⚠️ POSIBLE MALWARE - Se recomienda análisis profundo con MobSF")
            tasks.insert(0, AnalysisTask(
                tool="mobsf",
                description="Análisis automatizado completo estático y dinámico",
                priority=1,
                parameters={"scan_type": "full", "include_dynamic": True},
                estimated_time="30-60 min"
            ))
            recommended_tools.add('mobsf')
        
        # Agregar análisis dinámico recomendado si hay muchas protecciones
        if len(considerations) >= 3:
            tasks.append(AnalysisTask(
                tool="frida",
                description="Instrumentación dinámica para análisis de comportamiento",
                priority=3,
                parameters={"trace_methods": True, "hook_crypto": True},
                estimated_time="20-40 min"
            ))
            recommended_tools.add('frida')
        
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
