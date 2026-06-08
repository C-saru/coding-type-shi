FROM python:3.10-slim

LABEL description="APK Reverse Engineering System"
LABEL maintainer="Security Team"

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    openjdk-11-jdk-headless \
    android-sdk-build-tools \
    git \
    && rm -rf /var/lib/apt/lists/*

# Establecer variables de entorno
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV ANDROID_HOME=/usr/lib/android-sdk

# Descargar e instalar JADX
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/ \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui \
    && rm /tmp/jadx.zip

# Descargar e instalar Apktool
RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.9.0/apktool_2.9.0.jar -O /usr/local/bin/apktool.jar \
    && wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Instalar dependencias Python
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Crear directorios
RUN mkdir -p /app/input /app/output /app/reports

# Volumen para datos persistentes
VOLUME ["/app/input", "/app/output", "/app/reports"]

# Puerto para API (si se implementa)
EXPOSE 5000

CMD ["python", "-c", "print('APK Reverse System ready!')"]
