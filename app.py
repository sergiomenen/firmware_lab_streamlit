
import streamlit as st
from pathlib import Path
import json, io, base64, re
from device_sim import (
    get_firmware_version, get_settings, login,
    change_password, harden_settings, apply_firmware, reset_device
)
from crypto_utils import verify_signature

st.set_page_config(page_title="Firmware Vulnerable - Laboratorio IoT", page_icon="🛡️", layout="wide")

st.title("🛡️ Laboratorio: Firmware vulnerable y credenciales por defecto (IoT)")
st.caption("Actividad guiada para practicar remediación de firmware y contraseñas por defecto.")

with st.sidebar:
    st.header("⚙️ Controles del simulador")
    if st.button("Reiniciar dispositivo a estado vulnerable"):
        reset_device()
        st.success("Dispositivo restaurado a 1.0.0-vulnerable con admin/admin.")
    st.divider()
    st.markdown("**Archivos de ejemplo incluidos:**")
    st.code("public_key.pem\nfirmware_patched_v1.1.0.bin\nfirmware_patched_v1.1.0.sig", language="text")
    st.info("Puedes usar tus propios binarios y firmas si quieres.")

tabs = st.tabs([
    "1) Arranque",
    "2) Login por defecto",
    "3) Enumeración",
    "4) Cambio de contraseña",
    "5) Actualización de firmware (firmado)",
    "6) Verificación final",
    "📄 Evidencias & Plan (export)"
])

# 1) Arranque
with tabs[0]:
    st.subheader("1) Arranque: versión de firmware")
    ver = get_firmware_version()
    st.metric("Versión de firmware", ver)
    st.write("Toma una captura de esta pantalla como evidencia del primer arranque.")

# 2) Login por defecto
with tabs[1]:
    st.subheader("2) Intento de login con credenciales por defecto")
    u = st.text_input("Usuario", value="admin")
    p = st.text_input("Contraseña", value="admin", type="password")
    if st.button("Probar login"):
        ok = login(u, p)
        if ok:
            st.success("Login exitoso con credenciales por defecto (demostración de vulnerabilidad).")
        else:
            st.error("Login fallido. (Si ya cambiaste la contraseña, esto es esperado.)")
    st.info("En un entorno real, este paso solo se hace en laboratorio controlado.")

# 3) Enumeración
with tabs[2]:
    st.subheader("3) Enumeración de superficies y datos sensibles")
    s = get_settings()
    col1, col2 = st.columns(2)
    with col1:
        st.write("Ajustes de red / servicios")
        st.json({
            "wifi_ssid": s.get("wifi_ssid"),
            "ssh_enabled": s.get("ssh_enabled"),
            "telnet_enabled": s.get("telnet_enabled"),
            "ota_enabled": s.get("ota_enabled")
        })
    with col2:
        st.write("Datos sensibles (ejemplo de mala práctica)")
        st.json({
            "wifi_pass_plain": s.get("wifi_pass_plain"),
            "api_key_plain": s.get("api_key_plain")
        })
    st.warning("Observa secretos en claro y servicios de debug habilitados.")

# 4) Cambio de contraseña
with tabs[3]:
    st.subheader("4) Remediación: cambio de contraseña (mín. 12 caracteres)")
    new_pass = st.text_input("Nueva contraseña (mín. 12, mezcla de mayúsculas/minúsculas/dígitos/símbolos)", type="password")
    def strong(pw: str) -> bool:
        if len(pw) < 12: return False
        if not re.search(r"[A-Z]", pw): return False
        if not re.search(r"[a-z]", pw): return False
        if not re.search(r"[0-9]", pw): return False
        if not re.search(r"[^A-Za-z0-9]", pw): return False
        return True
    if st.button("Cambiar contraseña"):
        if strong(new_pass):
            change_password(new_pass)
            st.success("Contraseña actualizada y almacenada como hash (bcrypt). Primer arranque deshabilitado.")
        else:
            st.error("La contraseña no cumple la política de robustez.")

# 5) Actualización de firmware firmado
with tabs[4]:
    st.subheader("5) Remediación: actualizar firmware verificado (firma)")
    st.write("Sube el firmware **.bin** y su firma **.sig**, junto con la **clave pública** del fabricante (**public_key.pem**).")
    pub_pem = st.file_uploader("Clave pública (PEM)", type=["pem"])
    fw_bin = st.file_uploader("Firmware (.bin)", type=["bin"])
    fw_sig = st.file_uploader("Firma (.sig)", type=["sig"])
    target_version = st.text_input("Nueva versión (ej: 1.1.0-segura)", value="1.1.0-segura")
    if st.button("Verificar y aplicar update"):
        if not(pub_pem and fw_bin and fw_sig):
            st.error("Faltan archivos.")
        else:
            pub = pub_pem.read()
            data = fw_bin.read()
            sig = fw_sig.read()
            if verify_signature(pub, data, sig):
                apply_firmware(target_version)
                st.success(f"Firma válida ✓. Firmware actualizado a {target_version}.")
            else:
                st.error("Firma inválida. Update rechazado.")

# 6) Verificación final
with tabs[5]:
    st.subheader("6) Verificación final")
    st.write("Comprobar que las credenciales por defecto ya no funcionan y que el hardening está aplicado.")
    u2 = st.text_input("Usuario (final)", value="admin", key="u2")
    p2 = st.text_input("Contraseña (final)", type="password", key="p2")
    if st.button("Probar login (final)"):
        ok2 = login(u2, p2)
        if ok2:
            st.success("Login exitoso con la nueva contraseña.")
        else:
            st.info("Las credenciales probadas no funcionan (si usaste admin/admin, esto es el resultado esperado).")

    st.write("Hardening opcional")
    c1 = st.checkbox("Deshabilitar SSH", value=True)
    c2 = st.checkbox("Deshabilitar Telnet", value=True)
    c3 = st.checkbox("Habilitar OTA", value=True)
    if st.button("Aplicar hardening"):
        harden_settings(disable_ssh=c1, disable_telnet=c2, enable_ota=c3)
        st.success("Hardening aplicado. Secretos en claro removidos y servicios ajustados.")

# Evidencias & Plan
with tabs[6]:
    st.subheader("📄 Evidencias y plan técnico (export)")
    plan = st.text_area("Redacta aquí tu plan técnico (máx. 250 palabras). Sugerencia de estructura incluida por el profesor.",
        value=(
            "- Primer arranque: forzar cambio de credenciales y no permitir admin/admin.\n"
            "- OTA firmado: verificación de firma con clave pública embebida/secure element.\n"
            "- Almacenamiento de secretos: NVS cifrado o secure element.\n"
            "- Servicios a deshabilitar: telnet/ssh/console en PROD.\n"
            "- Rotación/revocación: política y mecanismo operativo.\n"
            "- Respuesta ante compromiso: aislamiento, revocación, re-flash firmado, investigación.\n"
        ),
        height=180
    )
    if st.button("Exportar evidencias (.md)"):
        ver = get_firmware_version()
        buf = io.StringIO()
        buf.write("# Evidencias de laboratorio\n\n")
        buf.write(f"- Versión de firmware actual: **{ver}**\n")
        buf.write("- Capturas: adiciona las imágenes tomadas durante los pasos 1–6.\n")
        buf.write("\n## Plan técnico (resumen)\n")
        buf.write(plan + "\n")
        md_bytes = buf.getvalue().encode()
        st.download_button("Descargar evidencias.md", data=md_bytes, file_name="evidencias_lab.md", mime="text/markdown")
