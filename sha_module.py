# ------------------------------
# sha_module.py
# SHA-256 & SHA-512 HASHING
# ------------------------------

from Crypto.Hash import SHA256, SHA512

def sha256_hash(data: bytes) -> str:
    return SHA256.new(data).hexdigest()

def sha512_hash(data: bytes) -> str:
    return SHA512.new(data).hexdigest()
