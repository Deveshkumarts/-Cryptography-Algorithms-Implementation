# ---------------------------------
# aes_module.py
# AES-256-GCM FILE ENCRYPTION
# ---------------------------------

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

AES_KEY_LEN = 32
PBKDF2_ITERS = 200000
IV_LEN = 12
TAG_LEN = 16

def aes_encrypt(password: str, data: bytes) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password.encode(), salt, dkLen=AES_KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    iv = get_random_bytes(IV_LEN)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return salt + iv + tag + ciphertext


def aes_decrypt(password: str, blob: bytes) -> bytes:
    salt = blob[:16]
    iv = blob[16:16 + IV_LEN]
    tag = blob[16 + IV_LEN : 16 + IV_LEN + TAG_LEN]
    ciphertext = blob[16 + IV_LEN + TAG_LEN:]

    key = PBKDF2(password.encode(), salt, dkLen=AES_KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    return cipher.decrypt_and_verify(ciphertext, tag)
