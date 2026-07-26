import re
from collections import Counter

# Logs de prueba que simulan actividad real de un servidor Linux/Windows
SAMPLE_LOGS = """
2026-07-26 08:12:01 IP: 192.168.1.50 - User: admin - Status: SUCCESS
2026-07-26 08:14:22 IP: 45.33.32.156 - User: root - Status: FAILED
2026-07-26 08:14:25 IP: 45.33.32.156 - User: root - Status: FAILED
2026-07-26 08:14:28 IP: 45.33.32.156 - User: admin - Status: FAILED
2026-07-26 08:14:31 IP: 45.33.32.156 - User: support - Status: FAILED
2026-07-26 08:15:00 IP: 10.0.0.12 - User: jtrujillo - Status: SUCCESS
2026-07-26 08:20:11 IP: 185.220.101.5 - User: root - Status: FAILED
2026-07-26 08:20:15 IP: 185.220.101.5 - User: root - Status: FAILED
2026-07-26 08:25:40 IP: 192.168.1.50 - User: jtrujillo - Status: SUCCESS
"""

def analyze_logs(log_data, threshold=3):
    print("=" * 60)
    print(" 🚨 SISTEMA DE ANÁLISIS DE LOGS & DETECCIÓN DE AMENAZAS")
    print("=" * 60 + "\n")

    # Expresión regular para extraer IP y Estado del intento
    pattern = r"IP:\s*([\d\.]+).*Status:\s*(\w+)"
    failed_attempts = Counter()
    
    lines = log_data.strip().split("\n")
    print(f"[*] Analizando {len(lines)} registros de eventos...\n")

    for line in lines:
        match = re.search(pattern, line)
        if match:
            ip, status = match.groups()
            if status == "FAILED":
                failed_attempts[ip] += 1

    print("📊 RESUMEN DE INTENTOS FALLIDOS POR IP:")
    print("-" * 40)
    for ip, count in failed_attempts.items():
        print(f" • IP: {ip:<15} | Fallos: {count}")

    print("\n⚠️  ALERTAS DE SEGURIDAD (Posible Ataque de Fuerza Bruta):")
    print("-" * 60)
    alerts = 0
    for ip, count in failed_attempts.items():
        if count >= threshold:
            print(f"[ALERT] ¡AMENAZA DETECTADA! La IP {ip} superó el umbral con {count} intentos fallidos.")
            alerts += 1

    if alerts == 0:
        print("[INFO] No se detectaron anomalías críticas.")

    print("\n" + "=" * 60)
    print("Análisis finalizado.")
    print("=" * 60)

if __name__ == "__main__":
    # Ejecutamos el análisis con un umbral de 3 fallos
    analyze_logs(SAMPLE_LOGS, threshold=3)
