# crypto/aes.py
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def encrypt_aes(key, plaintext, mode):
    backend = default_backend()
    cipher = None

    if mode == 'ecb':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    elif mode == 'cbc':
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        plaintext = pad(plaintext)
    elif mode == 'ofb':
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
    else:
        raise ValueError("Invalid encryption mode")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_aes(key, ciphertext, mode):
    backend = default_backend()
    cipher = None

    if mode == 'ecb':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    elif mode == 'cbc':
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    elif mode == 'ofb':
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
    else:
        raise ValueError("Invalid encryption mode")

    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    if mode == 'cbc':
        decrypted_text = unpad(decrypted_text)

    return decrypted_text

def decrypt_aes(key, ciphertext, mode):
    backend = default_backend()

    if mode == 'cbc':
        cipher = Cipher(algorithms.AES(key), modes.CBC(ciphertext[:16]), backend=backend)
    elif mode == 'ofb':
        cipher = Cipher(algorithms.AES(key), modes.OFB(ciphertext[:16]), backend=backend)
    else:
        raise ValueError("Invalid mode. Supported modes are: 'cbc', 'ofb'.")

    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    return plaintext.decode()



def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=10000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password)
    return key