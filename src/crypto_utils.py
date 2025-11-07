import base64
import typing as tp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt_value(plaintext: str, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(ct_bytes).decode()

def decrypt_value(ciphertext_b64: str, key: bytes, iv: bytes) -> str:
    ct_bytes = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

def encrypt_json_values(obj: tp.Any, key: bytes, iv: bytes):
    if isinstance(obj, dict):
        return {k: encrypt_json_values(v, key, iv) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [encrypt_json_values(x, key, iv) for x in obj]
    elif isinstance(obj, str):
        return encrypt_value(obj, key, iv)
    else:
        return obj

def decrypt_json_values(obj: tp.Any, key: bytes, iv: bytes):
    if isinstance(obj, dict):
        return {k: decrypt_json_values(v, key, iv) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decrypt_json_values(x, key, iv) for x in obj]
    elif isinstance(obj, str):
        try:
            return decrypt_value(obj, key, iv)
        except Exception:
            # not encrypted or not base64 – return as-is
            return obj
    else:
        return obj