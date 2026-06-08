# 🔍 APK Reverse Engineering System

Sistema automatizado para detección, planificación y ejecución de ingeniería inversa en archivos APK. Integra las mejores herramientas del sector (JADX, Frida, Ghidra, MobSF, etc.) en una arquitectura modular y escalable.

## 📋 Índice

- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso Básico](#-uso-básico)
- [Ejemplos](#-ejemplos)
- [Herramientas Soportadas](#-herramientas-soportadas)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Consideraciones Legales](#-consideraciones-legales)
- [Contribuir](#-contribuir)

---

## ✨ Características

### 🎯 Detección Inteligente
- Identificación automática de tecnologías: **Unity**, **React Native**, **Flutter**, **Xamarin**
- Detección de librerías nativas (.so) y ofuscación
- Análisis de permisos, componentes y certificados

### 🧠 Planificación Automática
- Generación de planes de análisis basados en características detectadas
- Selección inteligente de herramientas según el tipo de APK
- Priorización de tareas (estático → dinámico → especializado)

### ⚡ Ejecución Orquestada
- Integración con **10+ herramientas** de reverse engineering
- Bypass automático de protecciones comunes:
  - SSL Pinning
  - Root Detection
  - Debug Detection
  - Emulator Detection
- Ejecución paralela cuando es posible

### 📊 Reportes Multi-formato
- **JSON estructurado**: Para integración con otros sistemas
- **Markdown legible**: Para revisión humana
- Métricas detalladas y hallazgos clasificados por criticidad

---

## 🏗️ Arquitectura

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Ingester      │────▶│    Planner       │────▶│    Executor     │
│  (Validación)   │     │ (Planificación)  │     │ (Ejecución)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
  - Validar APK           - Detectar tech          - JADX/Apktool
  - Extraer metadata      - Seleccionar tools      - Frida/Objection
  - Identificar risks     - Generar plan           - Ghidra/Il2Cpp
```

### Módulos Principales

| Módulo | Responsabilidad |
|--------|----------------|
| `modules/ingester.py` | Validación, extracción de metadata y detección inicial |
| `modules/planner.py` | Análisis de características y generación de planes |
| `modules/executor.py` | Orquestación de herramientas y recopilación de resultados |
| `tools/static_analysis.py` | Wrappers para JADX, Apktool, Ghidra |
| `tools/dynamic_analysis.py` | Wrappers para Frida, Objection |
| `tools/specialized_tools.py` | Wrappers para Il2CppDumper, hermes-dec |
| `modules/main.py` | API unificada de alto nivel |

---

## 📦 Requisitos

### Requisitos del Sistema
- **SO**: Linux (recomendado), macOS, Windows (WSL2 recomendado)
- **Python**: 3.9 o superior
- **RAM**: Mínimo 4GB (8GB+ recomendado para Ghidra)
- **Disco**: 5GB+ de espacio libre

### Dependencias de Python
```bash
pip install -r requirements.txt
```

**Paquetes principales:**
- `androguard` - Análisis estático de APKs
- `frida-tools` - Instrumentación dinámica
- `requests` - Integración con APIs externas
- `rich` - Salida formateada en terminal

### Herramientas Externas (Opcionales pero Recomendadas)

| Herramienta | Uso | Instalación |
|-------------|-----|-------------|
| **JADX** | Decompilación DEX→Java | `apt install jadx` o [GitHub](https://github.com/skylot/jadx) |
| **Apktool** | Decode/Rebuild de APKs | `apt install apktool` o [Sitio oficial](https://ibotpeaches.github.io/Apktool/) |
| **Ghidra** | Análisis de binarios nativos | [Descargar](https://ghidra-sre.org/) |
| **Frida** | Instrumentación dinámica | `pip install frida-tools` |
| **Il2CppDumper** | Unity IL2CPP | [GitHub](https://github.com/perfare/il2cppdumper) |
| **hermes-dec** | React Native Hermes | [GitHub](https://github.com/P1sec/hermes-dec) |

> 💡 **Nota**: El sistema funciona sin todas las herramientas instaladas, pero habilitará solo las disponibles.

---

## 🚀 Instalación

### Opción 1: Instalación Local (Recomendada para Desarrollo)

```bash
# 1. Clonar el repositorio
cd /workspace/apk-reverse-system

# 2. Crear entorno virtual (opcional pero recomendado)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# o
venv\Scripts\activate     # Windows

# 3. Instalar dependencias de Python
pip install -r requirements.txt

# 4. Instalar herramientas externas (ejemplo en Ubuntu/Debian)
sudo apt update
sudo apt install -y jadx apktool wget unzip

# 5. Descargar Ghidra (opcional)
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/latest/ghidra_*.zip
unzip ghidra_*.zip
export GHIDRA_PATH=$(pwd)/ghidra_*

# 6. Verificar instalación
python -c "from modules.main import APKReverseSystem; print('✅ Sistema listo')"
```

### Opción 2: Usando Docker (Recomendada para Producción)

```bash
# 1. Construir imágenes Docker
docker-compose build

# 2. Iniciar servicios
docker-compose up -d

# 3. Ejecutar análisis
docker-compose exec analyzer python -c "
from modules.main import APKReverseSystem
system = APKReverseSystem()
results = system.analyze('/input/app.apk')
print(results)
"
```

**Volúmenes Docker:**
- `./input:/input` - Carpeta para subir APKs
- `./output:/output` - Resultados del análisis

### Opción 3: Instalación Rápida (Script Automático)

```bash
# Ejecutar script de instalación automática
chmod +x scripts/install.sh
./scripts/install.sh
```

Este script:
- Instala dependencias de Python
- Descarga e instala JADX, Apktool
- Configura variables de entorno
- Verifica la instalación

---

## 💻 Uso Básico

### API Python

#### Análisis Completo

```python
from modules.main import APKReverseSystem

# Inicializar sistema
system = APKReverseSystem()

# Ejecutar análisis completo
results = system.analyze("ruta/al/archivo.apk")

# Imprimir reporte en Markdown
print(results['report_markdown'])

# Acceder a datos estructurados
print(f"Tipo de app: {results['metadata']['app_type']}")
print(f"Herramientas usadas: {results['execution']['tools_used']}")
print(f"Hallazgos críticos: {len(results['findings']['critical'])}")
```

#### Escaneo Rápido

```python
# Análisis ligero (solo estático básico)
quick_results = system.quick_scan("ruta/al/archivo.apk")
print(quick_results['summary'])
```

#### Análisis Específico

```python
# Solo análisis estático
static_results = system.static_analysis("ruta/al/archivo.apk")

# Solo análisis dinámico (requiere dispositivo/emulador)
dynamic_results = system.dynamic_analysis(
    "ruta/al/archivo.apk",
    device_id="emulator-5554"
)

# Análisis especializado para Unity
unity_results = system.analyze_unity_app("ruta/al/archivo.apk")
```

### Línea de Comandos (CLI)

```bash
# Análisis completo
python modules/main.py analyze input/app.apk --output output/results.json

# Escaneo rápido
python modules/main.py quick-scan input/app.apk

# Solo análisis estático
python modules/main.py static input/app.apk --decompile

# Análisis dinámico con dispositivo específico
python modules/main.py dynamic input/app.apk --device emulator-5554

# Generar reporte en Markdown
python modules/main.py analyze input/app.apk --format markdown --output report.md
```

**Opciones CLI:**
```
--output, -o      Archivo de salida (JSON/Markdown)
--format, -f      Formato de salida (json/markdown/html)
--verbose, -v     Modo detallado
--tools           Listar herramientas disponibles
--help, -h        Mostrar ayuda
```

---

## 📚 Ejemplos

### Ejemplo 1: Análisis de App Estándar

```python
from modules.main import APKReverseSystem

system = APKReverseSystem()
results = system.analyze("samples/com.example.app.apk")

# Verificar si se detectó ofuscación
if results['metadata'].get('obfuscated'):
    print("⚠️ La app usa ofuscación (ProGuard/DexGuard)")

# Listar permisos peligrosos
for permission in results['metadata']['permissions']['dangerous']:
    print(f"❗ Permiso peligroso: {permission}")
```

### Ejemplo 2: Análisis de Juego Unity

```python
from modules.main import APKReverseSystem

system = APKReverseSystem()
results = system.analyze("samples/com.unitygame.apk")

if results['metadata']['app_type'] == 'unity':
    print("🎮 Juego Unity detectado")
    print(f"Versión de IL2CPP: {results['metadata']['unity_version']}")
    
    # Extraer metadata de IL2CPP
    il2cpp_info = results['specialized']['il2cppdumper']
    print(f"Métodos encontrados: {il2cpp_info['method_count']}")
```

### Ejemplo 3: Bypass Automático de Protecciones

```python
from tools.dynamic_analysis import FridaWrapper

frida = FridaWrapper()

# Aplicar todos los bypasses comunes
bypass_scripts = [
    'ssl_pinning_bypass',
    'root_detection_bypass',
    'debug_detection_bypass'
]

for script in bypass_scripts:
    result = frida.apply_script("com.target.app", script)
    if result['success']:
        print(f"✅ {script} aplicado correctamente")
```

### Ejemplo 4: Generación de Reporte Personalizado

```python
from modules.main import APKReverseSystem

system = APKReverseSystem()
results = system.analyze("input/app.apk")

# Guardar reporte JSON
import json
with open('output/analysis.json', 'w') as f:
    json.dump(results, f, indent=2)

# Guardar reporte Markdown
with open('output/report.md', 'w') as f:
    f.write(results['report_markdown'])

print("📊 Reportes generados en output/")
```

---

## 🛠️ Herramientas Soportadas

### Análisis Estático

| Herramienta | Estado | Descripción |
|-------------|--------|-------------|
| **JADX** | ✅ | Decompilador DEX a Java con soporte para recursos |
| **Apktool** | ✅ | Decode y rebuild de APKs, edición de smali |
| **Ghidra** | ✅ | Análisis de binarios nativos (.so), desensamblado avanzado |
| **Androguard** | ✅ | Análisis estático integrado (permisos, componentes, etc.) |

### Análisis Dinámico

| Herramienta | Estado | Descripción |
|-------------|--------|-------------|
| **Frida** | ✅ | Instrumentación dinámica, hooks en tiempo de ejecución |
| **Objection** | ✅ | Toolkit basado en Frida para testing sin código |
| **r2frida** | 🔶 | Integración Radare2 + Frida (configuración manual) |

### Herramientas Especializadas

| Herramienta | Estado | Caso de Uso |
|-------------|--------|-------------|
| **Il2CppDumper** | ✅ | Juegos/apps Unity con IL2CPP |
| **hermes-dec** | ✅ | Apps React Native con bytecode Hermes |
| **MobSF** | ✅ | Framework todo-en-uno (vía Docker/API) |
| **QBDI** | 🔶 | Instrumentación binaria dinámica avanzada |

**Leyenda:** ✅ Implementado | 🔶 Soporte parcial/pendiente

---

## 📁 Estructura del Proyecto

```
apk-reverse-system/
├── modules/
│   ├── __init__.py
│   ├── ingester.py          # Validación y detección
│   ├── planner.py           # Planificación inteligente
│   ├── executor.py          # Orquestación de herramientas
│   └── main.py              # API principal
├── tools/
│   ├── __init__.py
│   ├── static_analysis.py   # JADX, Apktool, Ghidra
│   ├── dynamic_analysis.py  # Frida, Objection
│   └── specialized_tools.py # Il2CppDumper, hermes-dec
├── scripts/
│   ├── install.sh           # Script de instalación
│   └── frida_scripts/       # Scripts Frida predefinidos
│       ├── ssl_pinning_bypass.js
│       ├── root_detection_bypass.js
│       └── debug_detection_bypass.js
├── samples/                 # APKs de ejemplo (no incluidos)
├── output/                  # Resultados de análisis
├── docs/
│   └── INSTALL.md           # Guía detallada de instalación
├── Dockerfile               # Contenedor principal
├── Dockerfile.tools         # Contenedor con herramientas
├── docker-compose.yml       # Orquestación Docker
├── requirements.txt         # Dependencias Python
├── .gitignore
└── README.md                # Este archivo
```

---

## ⚖️ Consideraciones Legales

### ⚠️ Aviso Importante

Este sistema está diseñado **exclusivamente** para:
- ✅ Análisis de seguridad de aplicaciones propias
- ✅ Auditorías de seguridad autorizadas
- ✅ Investigación académica y educativa
- ✅ Análisis de malware en entornos controlados

### Prohibiciones
- ❌ No usar para ingeniería inversa de software sin permiso explícito
- ❌ No distribuir aplicaciones protegidas por derechos de autor
- ❌ No violar términos de servicio de aplicaciones de terceros
- ❌ No usar para actividades ilegales o maliciosas

### Responsabilidad
El usuario es **única y exclusivamente responsable** del uso que dé a esta herramienta. Los desarrolladores no se hacen responsables de ningún uso indebido o ilegal.

### Marco Legal de Referencia
- **OWASP MASTG**: [Mobile Application Security Testing Guide](https://owasp.org/www-project-mobile-app-security/)
- **DMCA**: Digital Millennium Copyright Act (excepciones para investigación de seguridad)
- **GDPR**: Regulación de protección de datos (si se analizan datos personales)

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Sigue estos pasos:

1. **Fork** el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcion`)
3. Commit tus cambios (`git commit -m 'Añadir nueva función'`)
4. Push a la rama (`git push origin feature/nueva-funcion`)
5. Abre un **Pull Request**

### Áreas de Mejora Sugeridas
- [ ] Soporte para iOS (IPA analysis)
- [ ] Integración con más herramientas (Binja, IDA Pro)
- [ ] Interfaz web (Flask/FastAPI + React)
- [ ] Base de datos para almacenar análisis históricos
- [ ] Machine Learning para detección de patrones de malware
- [ ] Soporte para análisis de apps Flutter (.dll)

### Reportar Bugs
Usa la sección de **Issues** de GitHub con la plantilla proporcionada.

---

## 📞 Soporte y Comunidad

- **Documentación**: `/docs/INSTALL.md`
- **Issues**: Reporta bugs o solicita features en GitHub
- **Discusión**: Únete a las discusiones para preguntas generales

---

## 📄 Licencia

Este proyecto está licenciado bajo **MIT License**. Ver archivo `LICENSE` para más detalles.

---

## 🙏 Agradecimientos

- **OWASP MASTG** por la guía comprehensiva de seguridad móvil
- **Comunidad de Frida** por la excelente herramienta de instrumentación
- **Desarrolladores de JADX, Apktool, Ghidra** por sus herramientas open-source
- **Todos los contribuidores** de herramientas de reverse engineering

---

<div align="center">

**Hecho con ❤️ para la comunidad de seguridad móvil**

[⬆️ Volver al inicio](#-apk-reverse-engineering-system)

</div>
