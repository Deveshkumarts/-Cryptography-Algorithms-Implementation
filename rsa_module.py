# ---------------------------------
# rsa_module.py
# RSA TEXT ENCRYPTION (2048-bit)
# ---------------------------------

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt_text(public_key_pem: bytes, plaintext: str) -> str:
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt_text(private_key_pem: bytes, ciphertext_b64: str) -> str:
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    ciphertext = base64.b64decode(ciphertext_b64)
    return cipher.decrypt(ciphertext).decode()
