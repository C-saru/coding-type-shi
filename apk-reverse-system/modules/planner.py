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
        Crea un plan de análisis basado en la información del APK usando un Árbol de Decisión Dinámico.
        [INFO] Para futuras extensiones con Dexcalibur (Generación Dinámica de Hooks), se debe insertar
        la evaluación heurística de Dexcalibur inmediatamente después de Frida si se detecta ofuscación.
        """
        tasks = []
        recommended_tools = set()
        considerations = []
        
        if apk_info.has_unity_libs:
            considerations.append("Unity Framework detected.")
            tasks.append(AnalysisTask(tool="il2cppdumper", description="Extract IL2CPP metadata", priority=1, parameters={"target": "libil2cpp.so"}))
            tasks.append(AnalysisTask(tool="ghidra", description="Analyze Unity native libs", priority=2, parameters={"target": "libil2cpp.so"}))
            recommended_tools.update(['il2cppdumper', 'ghidra'])
        
        elif apk_info.has_react_native:
            considerations.append("React Native Framework detected.")
            tasks.append(AnalysisTask(tool="hermes-dec", description="Decompile Hermes bytecode", priority=1, parameters={"target": "index.android.bundle"}))
            recommended_tools.add('hermes-dec')

            if apk_info.is_split_apk:
                considerations.append("Split APKs (AAB) detected. Applying SplitAPKPatcher.")
                tasks.append(AnalysisTask(tool="split_patcher", description="Patch split APK via ELF injection", priority=2, parameters={"target_lib": "libreactnative.so", "mode": "script_wait"}))
                recommended_tools.add('split_patcher')

        elif getattr(apk_info, 'has_flutter', False):
            considerations.append("Flutter Framework detected.")
            tasks.append(AnalysisTask(tool="flutter_dump", description="Dump Flutter app", priority=1, parameters={"target": "libapp.so"}))
            recommended_tools.add('flutter_dump')

        else:
            considerations.append("Standard Android Application detected.")
            tasks.append(AnalysisTask(tool="jadx", description="Decompile DEX to Java", priority=1))
            tasks.append(AnalysisTask(tool="apktool", description="Decode resources", priority=2))
            recommended_tools.update(['jadx', 'apktool'])
        
        # Inyección dinámica si hay RASP o no hay root
        if not getattr(apk_info, 'root_available', True) and apk_info.has_native_libs:
            considerations.append("No root available and native libs detected. Scheduling Frida Gadget Injection for RASP evasion.")
            tasks.append(AnalysisTask(tool="frida_gadget", description="Inject Frida Gadget dynamically", priority=3, parameters={"mode": "wait"}))
            recommended_tools.add('frida_gadget')
        
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
