
# Laboratorio Streamlit — Firmware vulnerable y credenciales por defecto (IoT)

App local en **Streamlit** para practicar remediación de un dispositivo IoT con firmware vulnerable
y credenciales por defecto. Incluye un simulador simple, verificación de firma y exportación de evidencias.

## 🚀 Ejecución local

1) Crea y activa un entorno (opcional pero recomendado)
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
```

2) Instala dependencias
```bash
pip install -r requirements.txt
```

3) Inicia la app
```bash
streamlit run app.py
```

## 📂 Estructura
```
app.py
device_sim.py
crypto_utils.py
device_state.json
public_key.pem (para probar verificación)
firmware_patched_v1.1.0.bin
firmware_patched_v1.1.0.sig
requirements.txt
README.md
```

## 🧪 Flujo de la práctica
1. **Arranque**: visualiza la versión `1.0.0-vulnerable`.
2. **Login por defecto**: prueba `admin/admin` (solo con estado vulnerable).
3. **Enumeración**: observa secretos en claro y servicios de debug.
4. **Cambio de contraseña**: establece clave robusta (hash bcrypt).
5. **Update de firmware firmado**: sube `.bin`, `.sig` y `public_key.pem`. Si la firma es válida, aplica la nueva versión.
6. **Verificación**: comprueba que `admin/admin` ya no funciona. Aplica *hardening* (opcional).
7. **Evidencias & plan**: exporta un `.md` para entregar junto a tus capturas.

> Basado en la **Actividad: Firmware vulnerable y contraseñas por defecto** (guía de laboratorio).

## 🔒 Ética y alcance
Este material es para uso académico en un entorno controlado. No escanees ni intentes acceder a sistemas de terceros.
