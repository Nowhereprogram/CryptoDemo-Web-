import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from crypto.rsa import encrypt_rsa, generate_rsa_keypair


def encrypt_file_rsa(password, file_path, output_path):
    private_key, public_key = generate_rsa_keypair(password)

    with open(file_path, 'rb') as file:
        file_content_bytes = file.read()

    # 将文件内容转换为 Base64 编码的字符串
    file_content_str = base64.b64encode(file_content_bytes).decode('utf-8')

    # 使用公钥加密文件内容
    encrypted_content = encrypt_rsa(public_key, file_content_str)

    # 将加密后的内容写入指定文件
    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    return output_path