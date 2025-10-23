
import json
from pathlib import Path
from typing import Dict, Any
from crypto_utils import hash_password, verify_password

STATE_FILE = Path(__file__).parent / "device_state.json"

def _read_state() -> Dict[str, Any]:
    return json.loads(STATE_FILE.read_text())

def _write_state(s: Dict[str, Any]) -> None:
    STATE_FILE.write_text(json.dumps(s, indent=2))

def get_firmware_version() -> str:
    return _read_state()["firmware_version"]

def get_settings() -> Dict[str, Any]:
    s = _read_state()["settings"].copy()
    return s

def login(username: str, password: str) -> bool:
    s = _read_state()
    if username != s["admin_user"]:
        return False
    # Vulnerable path: if first_boot and plain is set, allow login with plain default
    if s.get("first_boot", False) and s.get("admin_pass_plain"):
        return password == s["admin_pass_plain"]
    # Secure path: require hash
    if s.get("admin_pass_hash"):
        return verify_password(password, s["admin_pass_hash"])
    return False

def change_password(new_password: str) -> None:
    s = _read_state()
    s["admin_pass_hash"] = hash_password(new_password)
    s["admin_pass_plain"] = ""  # remove plain text
    s["first_boot"] = False
    _write_state(s)

def harden_settings(disable_ssh: bool, disable_telnet: bool, enable_ota: bool) -> None:
    s = _read_state()
    s["settings"]["ssh_enabled"] = not disable_ssh
    s["settings"]["telnet_enabled"] = not disable_telnet
    s["settings"]["ota_enabled"] = enable_ota
    # remove secrets in plain text when hardening
    s["settings"]["wifi_pass_plain"] = ""
    s["settings"]["api_key_plain"] = ""
    _write_state(s)

def apply_firmware(version: str) -> None:
    s = _read_state()
    s["firmware_version"] = version
    _write_state(s)

def reset_device() -> None:
    s = {
        "firmware_version": "1.0.0-vulnerable",
        "admin_user": "admin",
        "admin_pass_plain": "admin",
        "admin_pass_hash": "",
        "first_boot": True,
        "settings": {
            "wifi_ssid": "LabNet",
            "wifi_pass_plain": "12345678",
            "api_key_plain": "ABCD-1234-SECRET",
            "ssh_enabled": True,
            "telnet_enabled": True,
            "ota_enabled": False
        }
    }
    _write_state(s)
