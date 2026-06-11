# 🚀 Guía de Instalación y Uso

## Requisitos del Sistema

### Mínimos
- Python 3.8+
- 4GB RAM (8GB recomendado)
- 10GB espacio libre
- Docker (opcional, para contenedores)

### Dependencias del Sistema
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    openjdk-11-jdk \
    android-sdk-build-tools \
    libmagic1 \
    adb

# macOS
brew install python openjdk android-platform-tools libmagic

# Windows
# Descargar e instalar:
# - Python desde python.org
# - JDK desde Oracle/OpenJDK
# - Android SDK Build Tools
```

## Instalación

### Opción 1: Instalación Local

```bash
# Clonar o descargar el repositorio
cd apk-reverse-system

# Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Instalar dependencias Python
pip install -r requirements.txt

# Instalar herramientas externas manualmente:
# 1. JADX: https://github.com/skylot/jadx/releases
# 2. Apktool: https://ibotpeaches.github.io/Apktool/install/
# 3. Frida: pip install frida-tools
# 4. Ghidra: https://ghidra-sre.org/
```

### Opción 2: Docker (Recomendado)

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

## Configuración de Herramientas

### JADX
```bash
# Descargar
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Verificar
jadx --version
```

### Apktool
```bash
# Descargar jar
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.0/apktool_2.9.0.jar -O apktool.jar

# Descargar script wrapper
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
chmod +x apktool

# Mover a PATH
sudo mv apktool apktool.jar /usr/local/bin/

# Verificar
apktool --version
```

### Frida
```bash
# Instalar herramientas Python
pip install frida-tools objection

# En dispositivo Android (requiere root):
adb push frida-server /data/local/tmp
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verificar
frida --version
frida-ps -U
```

### Ghidra (Opcional)
```bash
# Descargar desde https://ghidra-sre.org/
# Descomprimir
# Establecer variable de entorno
export GHIDRA_INSTALL_DIR=/opt/ghidra

# Para análisis headless:
analyzeHeadless project_dir project_name file.so
```

## Uso Básico

### API Python

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

### Línea de Comandos

```bash
# Análisis completo
python -c "from modules.main import APKReverseSystem; s = APKReverseSystem(); s.analyze('input/app.apk')"

# Con dispositivo conectado para análisis dinámico
python -c "from modules.main import APKReverseSystem; s = APKReverseSystem(); s.analyze('input/app.apk', device_connected=True)"
```

## Estructura de Directorios

```
apk-reverse-system/
├── input/              # APKs a analizar
├── output/             # Resultados intermedios
│   └── <hash>/        # Directorio por APK
│       ├── jadx_output/
│       ├── apktool_output/
│       ├── native_libs/
│       └── analysis_report.json
├── reports/            # Reportes finales
│   ├── <hash>_timestamp.json
│   └── <hash>_timestamp.md
├── modules/            # Módulos principales
├── tools/              # Wrappers de herramientas
└── config/             # Configuraciones
```

## Formatos de Salida

### JSON Report
Contiene toda la información estructurada del análisis.

### Markdown Report
Reporte legible para humanos con:
- Información general del APK
- Permisos solicitados
- Características detectadas
- Plan de análisis ejecutado
- Resultados por herramienta

## Solución de Problemas

### Error: libmagic no encontrado
```bash
# Ubuntu/Debian
sudo apt-get install libmagic1

# macOS
brew install libmagic

# Windows
# Instalar python-magic-bin
pip install python-magic-bin
```

### Error: Java no encontrado
```bash
# Verificar instalación
java -version

# Establecer JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

### Error: adb no encontrado
```bash
# Ubuntu/Debian
sudo apt-get install android-tools-adb

# macOS
brew install android-platform-tools
```

### Frida no detecta dispositivo
```bash
# Verificar conexión
adb devices

# Reiniciar adb server
adb kill-server
adb start-server

# Verificar frida-server
adb shell ps | grep frida
```

## Mejores Prácticas

1. **Entorno Aislado**: Usar siempre entorno virtual o Docker
2. **Dispositivo Test**: Usar emulador o dispositivo dedicado para testing
3. **Backups**: Mantener copias de APKs originales
4. **Legalidad**: Solo analizar apps propias o con autorización
5. **Resources**: Documentar hallazgos importantes

## Recursos Adicionales

- [OWASP MASTG](https://owasp.org/www-project-mobile-app-security/)
- [Frida Documentation](https://frida.re/docs/)
- [Android Reverse Engineering](https://github.com/user1342/Awesome-Android-Reverse-Engineering)

## Soporte

Para issues y contribuciones, revisar la documentación en `docs/` o abrir un issue en el repositorio.
