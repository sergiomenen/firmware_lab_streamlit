
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from passlib.hash import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(password: str, pw_hash: str) -> bool:
    try:
        return bcrypt.verify(password, pw_hash)
    except Exception:
        return False

def verify_signature(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
