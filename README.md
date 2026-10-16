# 🛡️ Búnker Pro Toolkit & Security Suite

Suite de herramientas de automatización, análisis de red, auditoría criptográfica y procesamiento de datos desarrollada en Python puro para entornos de alta eficiencia (Linux / Termux).

## 🚀 Características Principales
* **Cifrado Simétrico Nativo:** Implementación de derivación de claves robusta mediante PBKDF2-HMAC-SHA256 y cifrado por bloques con alta entropía.
* **Auditoría de Entropía:** Algoritmo optimizado para evaluar la fortaleza de contraseñas y claves de seguridad en bits.
* **Escaneo de Red Concurrente:** Módulo de diagnóstico de puertos abiertos mediante `ThreadPoolExecutor` y Sockets TCP.
* **Extracción de Patrones (Regex):** Motor de análisis para la detección masiva de direcciones IP, correos electrónicos y huellas criptográficas (MD5/SHA).

## ⚙️ Requisitos y Ejecución
El script opera íntegramente con la librería estándar de Python 3, garantizando compatibilidad total y rendimiento nativo sin dependencias externas complejas.

```bash
python3 scripts/bunker_pro.py
cat << 'EOF' > README.md
# 🛡️ Búnker Pro Toolkit & Security Suite

Suite de herramientas de automatización, análisis de red, auditoría criptográfica, monitoreo de integridad y procesamiento de logs desarrollada en Python puro para entornos de alta eficiencia (Linux / Termux).

## 🚀 Características Principales
* **Cifrado Simétrico Nativo:** Implementación de derivación de claves robusta mediante PBKDF2-HMAC-SHA256 y cifrado por bloques con alta entropía.
* **Auditoría de Entropía:** Algoritmo optimizado para evaluar la fortaleza de contraseñas y claves de seguridad en bits.
* **Escaneo de Red Concurrente:** Módulo de diagnóstico de puertos abiertos mediante `ThreadPoolExecutor` y Sockets TCP.
* **Extracción de Patrones (Regex):** Motor de análisis para la detección masiva de direcciones IP, correos electrónicos y huellas criptográficas (MD5/SHA).
* **Monitoreo de Integridad (FIM):** Módulo basado en hashes SHA-256 para control de cambios no autorizados en archivos del sistema.
* **Análisis Heurístico de Logs:** Motor de reglas para la detección de ataques en tiempo real (SQL Injection, Força Bruta y Path Traversal).

## ⚙️ Requisitos y Ejecución
El script opera íntegramente con la librería estándar de Python 3, garantizando compatibilidad total y rendimiento nativo sin dependencias externas complejas.

```bash
python3 scripts/bunker_pro.py
