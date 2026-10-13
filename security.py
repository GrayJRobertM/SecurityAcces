"""Cryptographic primitives; no credentials are logged."""
import hashlib
import hmac
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CATEGORIES = (string.ascii_uppercase, string.ascii_lowercase, string.digits, '!@#$%&*+-=?')

def generate_password(length=15):
    if not isinstance(length, int) or isinstance(length, bool) or not 15 <= length <= 64:
        raise ValueError('La longitud debe estar entre 15 y 64 caracteres.')
    alphabet = ''.join(CATEGORIES)
    # Rejection sampling keeps uniform distribution across compliant passwords.
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in value) for group in CATEGORIES):
            return value

def fingerprint(key, password):
    return hmac.new(key, b'password-fingerprint\x00' + password.encode(), hashlib.sha256).hexdigest()

def seal(key, identifier, password):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, password.encode(), identifier.encode())

def unseal(key, identifier, payload):
    return AESGCM(key).decrypt(payload[:12], payload[12:], identifier.encode()).decode()
