# 🛡️ Security Log Analyzer & Threat Detector

Herramienta automatizada en Python orientada a operaciones de seguridad (SOC) para el procesamiento de logs de servidor y la detección temprana de ataques de fuerza bruta.

---

## 🎯 Funcionalidades
- Parseo e interpretación de eventos de autenticación mediante Expresiones Regulares (RegEx).
- Conteo y agregación de intentos fallidos de inicio de sesión agrupados por dirección IP.
- Generación de alertas automáticas ante IPs sospechosas que superan el umbral configurado.

---

## 💻 Ejecución
```bash
python log_analyzer.py
