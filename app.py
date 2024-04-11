import os
import base64
import sys
from flask import send_from_directory

from flask import Flask, render_template, request, jsonify, session, send_file
from flask import Flask, render_template, request
from crypto.aes import encrypt_aes, decrypt_aes, derive_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto.file_crypto import  encrypt_file_rsa
from crypto.rsa import generate_rsa_keypair, encrypt_rsa, decrypt_rsa



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PUBLIC_KEY_FOLDER'] = 'public_keys'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'


app.secret_key = os.urandom(24)

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt data using RSA
def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# Function to decrypt data using RSA
def rsa_decrypt(private_key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/symmetric/aes', methods=['GET', 'POST'])
def encrypt_aes_route():
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        password = request.form['password']
        mode = request.form['mode']

        salt = os.urandom(16)
        key = derive_key(password.encode(), salt)


        try:
            cipher = encrypt_aes(key, plaintext.encode(), mode)

            encoded_salt = base64.b64encode(salt).decode()
            encoded_result = base64.b64encode(cipher).decode()

            return render_template('aes.html', plaintext=plaintext, encoded_salt=encoded_salt, encrypted_text=encoded_result,key=key)
        except Exception as e:
            error_message = f"Error during encryption: {e}"
            return render_template('aes.html', error_message=error_message)

    return render_template('aes.html', plaintext="", encoded_salt="", encrypted_text="", error_message="",key="")

@app.route('/symmetric/aes/decrypt', methods=['POST'])
def decrypt_aes_route():
    if request.method == 'POST':
        encoded_salt = request.form['encoded_salt']
        encrypted_text = request.form['encrypted_text']
        plaintext = request.form['plaintext']
        password = request.form['password']
        key = request.form['key']
        mode = request.form['mode']

        try:
            salt = base64.b64decode(encoded_salt)

            ciphertext = base64.b64decode(encrypted_text)

            decrypted_text = decrypt_aes(key, ciphertext, mode)

            if decrypted_text is not None:
                return render_template('aes.html', decrypted_text=decrypted_text, decryption_success=True)
            else:
                error_message = "Decryption failed. Please check your key and ciphertext."
                return render_template('aes.html', error_message=error_message)
        except Exception as e:
            error_message = f"Error during decryption: {e}"
            return render_template('aes.html', error_message=error_message)

    return render_template('aes.html', decrypted_text="", error_message="")

@app.route('/asymmetric/rsa', methods=['GET', 'POST'])
def encrypt_rsa_route():
    if request.method == 'POST':
        plaintext = request.form['rsa_plaintext']
        password = request.form['rsa_password']

        private_key, public_key = generate_rsa_keypair(password)


        try:
            encrypted_text = encrypt_rsa(public_key, plaintext)

            encoded_result = base64.b64encode(encrypted_text).decode()

            return render_template('rsa.html', plaintext=plaintext, public_key=public_key, rsa_encrypted_text=encoded_result)
        except Exception as e:
            error_message = f"Error during RSA encryption: {e}"
            return render_template('rsa.html', error_message=error_message)

    return render_template('rsa.html', plaintext="", public_key="", rsa_encrypted_text="", error_message="")


@app.route('/asymmetric/rsa/decrypt', methods=['POST'])
def decrypt_rsa_route():
    global private_key
    if request.method == 'POST':
        rsa_encrypted_text = request.form['rsa_encrypted_text']

        try:
            rsa_decrypted_text = decrypt_rsa(private_key, base64.b64decode(rsa_encrypted_text))

            return render_template('rsa.html', rsa_decrypted_text=rsa_decrypted_text, decryption_success=True)
        except Exception as e:
            error_message = f"Error during RSA decryption: {e}"
            return render_template('rsa.html', error_message=error_message)

    return render_template('rsa.html', rsa_decrypted_text="", error_message="")

@app.route('/file_crypto', methods=['GET', 'POST'])
def file_crypto_route():
    if request.method == 'POST':
        password = request.form['password']


        uploaded_file = request.files['file']

        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted',
                                           uploaded_file.filename + '_encrypted')

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', uploaded_file.filename + '_encrypted')
        try:
            encrypt_file_rsa(password,file_path, output_path)

            return render_template('file.html', encrypted_file_path=encrypted_file_path)
        except Exception as e:
            error_message = f"Error during file encryption: {e}"
            return render_template('file.html', error_message=error_message)

    return render_template('file.html', encrypted_file_path="", error_message="")

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
