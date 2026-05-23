# python_crypto.py — fixture for acdi source scanner tests
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib

def generate_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

def generate_ec():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def hash_old(data: bytes):
    # SHA-1 is deprecated for cryptographic use
    h = hashes.Hash(hashes.SHA1(), backend=default_backend())
    h.update(data)
    return h.finalize()

def hash_md5(data: bytes):
    # MD5 used only for checksums here
    return hashlib.md5(data).hexdigest()

def hash_modern(data: bytes):
    return hashlib.sha256(data).hexdigest()
