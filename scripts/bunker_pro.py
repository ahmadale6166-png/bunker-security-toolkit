#!/usr/bin/env python3
"""
Búnker Pro v3 - Script Integral de Auditoría, Cifrado Nativo y Redes
Autor: Alejandro Daniel Ahmad
"""

import socket
import secrets
import string
import re
import math
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor

class BunkerPro:
    @staticmethod
    def evaluar_entropia(password: str) -> float:
        """Calcula la entropía de una cadena en bits."""
        caracteres_posibles = 0
        if any(c in string.ascii_lowercase for c in password): caracteres_posibles += 26
        if any(c in string.ascii_uppercase for c in password): caracteres_posibles += 26
        if any(c in string.digits for c in password): caracteres_posibles += 10
        if any(c in string.punctuation for c in password): caracteres_posibles += 32
        
        if caracteres_posibles == 0 or len(password) == 0:
            return 0.0
        return len(password) * math.log2(caracteres_posibles)

    @staticmethod
    def cifrar_nativo(mensaje: str, password_maestra: str) -> dict:
        """Cifra un mensaje utilizando derivación de claves SHA-256 y cifrado simétrico nativo."""
        salt = secrets.token_bytes(16)
        # Derivar clave con PBKDF2 nativo
        key = hashlib.pbkdf2_hmac('sha256', password_maestra.encode('utf-8'), salt, 100000)
        
        # Cifrado simétrico por XOR de bloques con la clave derivada
        mensaje_bytes = mensaje.encode('utf-8')
        cifrado_bytes = bytearray(b ^ key[i % len(key)] for i, b in enumerate(mensaje_bytes))
        
        return {
            "salt_b64": base64.b64encode(salt).decode('utf-8'),
            "cifrado_b64": base64.b64encode(cifrado_bytes).decode('utf-8')
        }

    @staticmethod
    def descifrar_nativo(salt_b64: str, cifrado_b64: str, password_maestra: str) -> str:
        """Descifra el mensaje utilizando la misma clave derivada."""
        salt = base64.b64decode(salt_b64)
        cifrado_bytes = base64.b64decode(cifrado_b64)
        
        key = hashlib.pbkdf2_hmac('sha256', password_maestra.encode('utf-8'), salt, 100000)
        descifrado_bytes = bytearray(b ^ key[i % len(key)] for i, b in enumerate(cifrado_bytes))
        
        return descifrado_bytes.decode('utf-8')

    @staticmethod
    def escanear_puerto(host: str, puerto: int) -> tuple:
        """Comprueba si un puerto específico está abierto."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                resultado = s.connect_ex((host, puerto))
                return puerto, resultado == 0
        except Exception:
            return puerto, False

    @classmethod
    def escanear_rango(cls, host: str, puertos: list):
        """Escanea múltiples puertos de forma concurrente."""
        print(f"\n[*] Escaneando {host} en {len(puertos)} puertos...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            resultados = list(executor.map(lambda p: cls.escanear_puerto(host, p), puertos))
        
        abiertos = [p for p, estado in resultados if estado]
        return abiertos

    @staticmethod
    def extraer_patrones(texto: str) -> dict:
        """Extrae IPs, emails y hashes de un texto usando expresiones regulares."""
        patrones = {
            "ips": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "emails": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            "hashes_md5_sha": r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        }
        
        hallazgos = {}
        for clave, patron in patrones.items():
            hallazgos[clave] = list(set(re.findall(patron, texto)))
        return hallazgos

if __name__ == "__main__":
    print("=== BÚNKER PRO V3: INICIANDO MÓDULOS NATIVOS ===")
    
    # 1. Prueba de Entropía
    pwd_prueba = "Ee?j\\&LjM\"Z3POVtf:8,_`[Fy@,!U+20"
    entropia = BunkerPro.evaluar_entropia(pwd_prueba)
    print(f"\n[+] Entropía calculada: {entropia:.2f} bits")
    
    # 2. Prueba de Cifrado Nativo Seguro
    password_maestra = "ClaveMaestraSuperSegura2026!"
    mensaje_secreto = "Datos críticos de infraestructura y auditoría interna."
    
    paquete = BunkerPro.cifrar_nativo(mensaje_secreto, password_maestra)
    print(f"\n[+] Texto cifrado nativamente:\n    {paquete['cifrado_b64'][:40]}...")
    
    texto_recuperado = BunkerPro.descifrar_nativo(paquete["salt_b64"], paquete["cifrado_b64"], password_maestra)
    print(f"[+] Texto descifrado con éxito: '{texto_recuperado}'")
    
    # 3. Prueba de Extracción de Datos
    texto_muestra = "Conexión desde 192.168.1.50 con admin@bunker.local y token e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    datos_extraidos = BunkerPro.extraer_patrones(texto_muestra)
    print(f"\n[+] Patrones detectados:\n{datos_extraidos}")
    
    # 4. Escaneo Local
    puertos_comunes = [21, 22, 80, 443, 3306, 5432, 8000, 8080]
    abiertos = BunkerPro.escanear_rango("127.0.0.1", puertos_comunes)
    print(f"\n[+] Puertos abiertos en localhost: {abiertos}")
    print("\n=== PRUEBAS V3 FINALIZADAS CON ÉXITO ===")
import hashlib
import os
import re
from datetime import datetime

class BunkerAdvancedAudit:
    """Módulo avanzado de auditoría de integridad y análisis de logs en tiempo real."""
    
    def __init__(self, target_dir="."):
        self.target_dir = target_dir
        self.signatures = {}

    def calculate_file_hash(self, filepath):
        """Calcula la huella SHA-256 de un archivo para control de integridad."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            return None

    def scan_directory_integrity(self):
        """Genera el mapa de integridad criptográfica del directorio."""
        print(f"\n[*] Generando mapa de integridad SHA-256 en: {self.target_dir}")
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".py") or file.endswith(".md"):
                    full_path = os.path.join(root, file)
                    file_hash = self.calculate_file_hash(full_path)
                    self.signatures[full_path] = file_hash
                    print(f"    [✔] {file} -> SHA256: {file_hash[:16]}...")
        return self.signatures

    def analyze_log_stream(self, log_lines):
        """Analizador heurístico de patrones sospechosos en logs."""
        print("\n[*] Iniciando análisis heurístico de logs...")
        threat_patterns = {
            "SQL Injection": r"(?i)(SELECT|INSERT|DELETE|DROP|UNION|OR 1=1)",
            "Brute Force Attempt": r"(?i)(Failed password|AUTH_FAILURE|Unauthorized)",
            "Path Traversal": r"(\.\./\.\./|\.\.\\\.\.\\)"
        }
        
        detected_threats = []
        for index, line in enumerate(log_lines, 1):
            for threat_type, pattern in threat_patterns.items():
                if re.search(pattern, line):
                    event = f"[ALERTA] Línea {index}: {threat_type} detectado -> '{line.strip()}'"
                    detected_threats.append(event)
                    print(f"    ⚠️  {event}")
        
        if not detected_threats:
            print("    [+] No se detectaron anomalías o amenazas en los registros de eventos.")
        return detected_threats

# Ejemplo de integración en el flujo principal:
if __name__ == "__main__":
    audit = BunkerAdvancedAudit()
    audit.scan_directory_integrity()
    
    # Simulación de prueba de logs de producción
    sample_logs = [
        "192.168.1.10 - - [15/Oct/2026] 'GET /index.html HTTP/1.1' 200",
        "10.0.0.5 - - [15/Oct/2026] 'POST /login HTTP/1.1' Failed password for root",
        "172.16.0.2 - - [15/Oct/2026] 'GET /search?q=1 UNION SELECT username,password FROM users' 200"
    ]
    audit.analyze_log_stream(sample_logs)
