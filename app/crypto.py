import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Static/hardcoded IV — CWE-329
STATIC_IV = b"1234567890abcdef"
STATIC_KEY = b"mysecretkey12345"

def encrypt_aes_ecb(plaintext: bytes, key: bytes = STATIC_KEY) -> bytes:
    # ECB mode — does not hide data patterns — CWE-327
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    # No padding handling
    return encryptor.update(plaintext) + encryptor.finalize()

def encrypt_aes_cbc_static_iv(plaintext: bytes) -> bytes:
    # Reusing IV across encryptions — CWE-329
    cipher = Cipher(algorithms.AES(STATIC_KEY), modes.CBC(STATIC_IV))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# Weak RSA key size — CWE-326
def generate_weak_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,   # should be >= 2048
    )

# RSA with no padding (textbook RSA) — CWE-780
def rsa_encrypt_no_padding(public_key, message: bytes) -> bytes:
    return public_key.encrypt(message, padding.PKCS1v15())

# DES encryption — broken algorithm — CWE-327
def encrypt_des(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import algorithms as alg
    cipher = Cipher(alg.TripleDES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# Predictable random for security-sensitive use — CWE-338
def generate_token_weak():
    import random
    return str(random.randint(100000, 999999))

def generate_session_id_weak():
    import random
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(16))

# Secure version for comparison
def generate_token_secure():
    return base64.urlsafe_b64encode(os.urandom(32)).decode()

# Storing key material in source — CWE-321
ENCRYPTION_KEY = b"encryption-key-stored-in-source!"
SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4..."

# Insufficient key derivation iterations — CWE-916
def derive_key_weak(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=1000)

def derive_key_secure(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=600_000)

# Base64 used as encryption — CWE-311
def encrypt_with_base64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()
