# 🔍 APK Reverse Engineering System

Sistema automatizado para detección, planificación y ejecución de ingeniería inversa en archivos APK. Integra las mejores herramientas del sector (JADX, Frida, Ghidra, MobSF, etc.) en una arquitectura modular y escalable.

## 📋 Índice
- [Características](#-características)
- [Versiones Disponibles](#-versiones-disponibles)
- [Arquitectura](#-arquitectura)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Herramientas Soportadas](#-herramientas-soportadas)
- [Estructura del Proyecto](#-estructura-del-proyecto)

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

## 🔄 Versiones Disponibles

### **Versión Terminal (Original)**
Interfaz de línea de comandos tradicional para análisis automatizado. Ideal para:
- Scripts y automatización
- Integración en pipelines CI/CD
- Uso en servidores sin interfaz gráfica

**Archivo principal**: `modules/main.py` o `super_pipeline.py`

### **Versión Web ("cheeks")**
Interfaz web moderna con Flask para gestión visual de análisis. Ideal para:
- Usuarios que prefieren interfaz gráfica
- Monitoreo en tiempo real de tareas
- Gestión de múltiples análisis simultáneos
- Visualización histórica de reportes

**Archivo principal**: `app.py`

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
| `app.py` | Servidor web Flask (versión "cheeks") |

---

## 📦 Requisitos

### Requisitos del Sistema
- **SO**: Linux (recomendado), macOS, Windows (WSL2 recomendado)
- **Python**: 3.9 o superior
- **RAM**: Mínimo 4GB (8GB+ recomendado para Ghidra)
- **Disco**: 5GB+ de espacio libre

### Dependencias de Python

#### **Comunes (Ambas Versiones)**
```bash
pip install -r requirements.txt
```

**Paquetes principales**:
- `androguard` - Análisis estático de APKs
- `frida-tools` - Instrumentación dinámica
- `requests` - Integración con APIs externas
- `rich` - Salida formateada en terminal
- `pydantic` - Validación de datos
- `python-magic` - Detección de tipos de archivo
- `xmltodict` - Parseo de XML
- `lief` - Instrumentación binaria ELF

#### **Exclusivas Versión Web ("cheeks")**
```bash
pip install flask werkzeug
```

**Paquetes adicionales**:
- `flask` - Framework web
- `werkzeug` - Utilidades de seguridad web

### Herramientas Externas (Opcionales pero Recomendadas)

| Herramienta | Uso | Instalación |
|-------------|-----|-------------|
| **JADX** | Decompilación DEX→Java | `apt install jadx` o [GitHub](https://github.com/skylot/jadx) |
| **Apktool** | Decode/Rebuild de APKs | `apt install apktool` o [Sitio oficial](https://ibotpeaches.github.io/Apktool/) |
| **Ghidra** | Análisis de binarios nativos | [Descargar](https://ghidra-sre.org/) |
| **Frida** | Instrumentación dinámica | `pip install frida-tools` |
| **Il2CppDumper** | Unity IL2CPP | [GitHub](https://github.com/perfare/il2cppdumper) |
| **hermes-dec** | React Native Hermes | [GitHub](https://github.com/P1sec/hermes-dec) |
| **zipalign** | Alineación de APKs | `apt install zipalign` (android-sdk-build-tools) |
| **apksigner** | Firma de APKs | `apt install apksigner` (android-sdk-build-tools) |

> 💡 **Nota**: El sistema funciona sin todas las herramientas instaladas, pero habilitará solo las disponibles.

---

## 🚀 Instalación

### **Opción 1: Versión Terminal (Original)**

```bash
# 1. Clonar el repositorio
cd /workspace/apk-reverse-system

# 2. Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# o
venv\Scripts\activate     # Windows

# 3. Instalar dependencias comunes
pip install -r requirements.txt

# 4. Instalar herramientas externas manualmente:
# 1. JADX: https://github.com/skylot/jadx/releases
# 2. Apktool: https://ibotpeaches.github.io/Apktool/install/
# 3. Frida: pip install frida-tools
# 4. Ghidra: https://ghidra-sre.org/
# 5. zipalign y apksigner: sudo apt install android-sdk-build-tools

# 5. Verificar instalación
python -c "from modules.main import APKReverseSystem; print('✅ Sistema terminal listo')"
```

### **Opción 2: Versión Web ("cheeks")**

```bash
# 1. Clonar el repositorio
cd /workspace/apk-reverse-system

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/macOS

# 3. Instalar dependencias comunes + web
pip install -r requirements.txt
pip install flask werkzeug

# 4. Instalar herramientas externas (mismo paso que versión terminal)
# ... (ver paso 4 de Opción 1)

# 5. Verificar instalación
python -c "from app import app; print('✅ Sistema web listo')"
```

### **Opción 3: Docker (Recomendado para Producción)**

```bash
# Construir imagen principal
docker build -t apk-reverse .

# Construir imagen con herramientas completas
docker build -f Dockerfile.tools -t apk-reverse-tools .

# Usar docker-compose
docker-compose up -d

# Ejecutar análisis en contenedor
docker run --rm -v $(pwd)/input:/app/input -v $(pwd)/output:/app/output apk-reverse python modules/main.py
```

---

## 💻 Uso

### **Versión Terminal**

#### API Python

```python
from modules.main import APKReverseSystem

# Inicializar sistema
system = APKReverseSystem()

# Análisis completo
results = system.analyze("input/app.apk")

# Escaneo rápido (solo estático)
quick = system.quick_scan("input/app.apk")

# Ver historial de análisis
history = system.list_analyzed_apks()

# Acceder a resultados
print(f"Package: {results['apk_info']['package_name']}")
print(f"Tareas exitosas: {results['execution_results']['summary']['successful']}")
```

#### Línea de Comandos

```bash
# Análisis completo
python -c "from modules.main import APKReverseSystem; s = APKReverseSystem(); s.analyze('input/app.apk')"

# Con dispositivo conectado para análisis dinámico
python -c "from modules.main import APKReverseSystem; s = APKReverseSystem(); s.analyze('input/app.apk', device_connected=True)"

# Análisis de app instalada en dispositivo (requiere ADB)
python super_pipeline.py com.example.app
```

### **Versión Web ("cheeks")**

#### Iniciar Servidor

```bash
# Activar entorno virtual
source venv/bin/activate

# Iniciar servidor web
python app.py

# El servidor estará disponible en:
# http://localhost:5000
```

#### Características de la Interfaz Web

1. **Dashboard Principal**
   - Visualización de análisis en tiempo real
   - Historial de aplicaciones analizadas
   - Estado de tareas en ejecución

2. **Métodos de Análisis**
   - **Extracción desde dispositivo**: Ingresa el package name y extrae automáticamente vía ADB
   - **Carga de APK local**: Sube un archivo APK directamente desde tu computadora

3. **Gestión de Reportes**
   - Visualización de reportes en Markdown
   - Descarga de reportes en JSON o Markdown
   - Búsqueda por package name o hash SHA256

4. **Monitoreo en Vivo**
   - Polling automático cada 3 segundos
   - Indicadores de estado: queued, running, completed, failed
   - Fase actual del análisis (ingest, analyzing, done)

---

## 📚 Ejemplos

### Ejemplo 1: Análisis de App Estándar (Terminal)

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

### Ejemplo 3: Uso de la API Web

```bash
# 1. Iniciar servidor
python app.py &

# 2. Analizar vía curl (extracción desde dispositivo)
curl -X POST http://localhost:5000/analyze/package \
  -d "package_name=com.example.app" \
  -d "device_connected=true"

# 3. Subir APK local
curl -X POST http://localhost:5000/analyze/file \
  -F "apk_file=@/path/to/app.apk"

# 4. Consultar estado de tarea
curl http://localhost:5000/tasks/<task_id>

# 5. Descargar reporte
curl http://localhost:5000/report/download/<apk_hash>/json -o report.json
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
│   └── main.py              # API principal (Terminal)
├── tools/
│   ├── __init__.py
│   ├── static_analysis.py   # JADX, Apktool, Ghidra
│   ├── dynamic_analysis.py  # Frida, Objection
│   └── specialized_tools.py # Il2CppDumper, hermes-dec
├── templates/               # (Solo versión Web)
│   ├── index.html          # Dashboard principal
│   ├── report.html         # Visualización de reportes
│   └── report.html         # Plantilla visor
├── scripts/
│   ├── install.sh          # Script de instalación
│   └── frida_scripts/      # Scripts Frida predefinidos
│       ├── ssl_pinning_bypass.js
│       ├── root_detection_bypass.js
│       └── debug_detection_bypass.js
├── samples/                 # APKs de ejemplo (no incluidos)
├── output/                  # Resultados de análisis
├── input/                   # APKs a analizar
├── reports/                 # Reportes generados
├── app.py                   # Servidor web Flask (Web)
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
- [ ] ~~Interfaz web (Flask/FastAPI + React)~~ ✅ Implementada en "cheeks"
- [ ] Base de datos para almacenar análisis históricos
- [ ] Machine Learning para detección de patrones de malware
- [ ] Soporte para análisis de apps Flutter (.dll)

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
