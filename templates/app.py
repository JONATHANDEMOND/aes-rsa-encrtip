from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import io
import os

app = Flask(__name__, static_url_path='/static', static_folder='templates/static')
CORS(app, resources={r"/*": {"origins": "*"}})  # Configura CORS para permitir solicitudes desde cualquier origen

# Ruta para almacenar archivos cifrados
DOWNLOAD_DIR = r'D:\Usuarios\Jonathan\Downloads'

# Función para encriptar datos con AES
def encrypt_data_with_aes(data, key):
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return cipher_aes.nonce + tag + ciphertext

@app.route('/encrypt_text_aes', methods=['POST'])
def encrypt_text_aes():
    try:
        data = request.get_json()
        if not data or 'plaintext' not in data:
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        plaintext = data.get('plaintext', '').encode()

        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        response_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'key': base64.b64encode(key).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode()
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f'Error en /encrypt_text_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_text_aes', methods=['POST'])
def decrypt_text_aes():
    try:
        data = request.get_json()
        key = base64.b64decode(data.get('key', ''))
        nonce = base64.b64decode(data.get('nonce', ''))
        tag = base64.b64decode(data.get('tag', ''))
        ciphertext = base64.b64decode(data.get('ciphertext', ''))
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return jsonify({'plaintext': decrypted_data.decode('utf-8')})
    
    except (ValueError, KeyError, TypeError) as e:
        print(f'Error en /decrypt_text_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Decryption failed. Invalid data or incorrect key/nonce/tag.'}), 400

    except Exception as e:
        print(f'Error en /decrypt_text_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/encrypt_file_aes', methods=['POST'])
def encrypt_file_aes():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        file_content = file.read()

        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(file_content)

        encrypted_file = io.BytesIO(cipher.nonce + tag + ciphertext)

        response_data = {
            'filename': file.filename + '.enc',
            'key': base64.b64encode(key).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode()
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f'Error en /encrypt_file_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_file_aes', methods=['POST'])
def decrypt_file_aes():
    try:
        if not all(k in request.form for k in ('key', 'nonce', 'tag')):
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400
        
        key = base64.b64decode(request.form['key'])
        nonce = base64.b64decode(request.form['nonce'])
        tag = base64.b64decode(request.form['tag'])

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        ciphertext = file.read()

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        decrypted_file = io.BytesIO(decrypted_data)

        return send_file(decrypted_file, as_attachment=True, download_name='decrypted_file', mimetype='application/octet-stream')

    except Exception as e:
        print(f'Error en /decrypt_file_aes: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/download_encrypted_file', methods=['POST'])
def download_encrypted_file():
    data = request.get_json()
    filename = data.get('filename')
    file_path = os.path.join(DOWNLOAD_DIR, filename)  # Ajusta la ruta

    if not os.path.isfile(file_path):
        return jsonify({'error': 'Archivo no encontrado'}), 404

    return send_file(file_path, as_attachment=True)

@app.route('/encrypt_rsa', methods=['POST'])
def encrypt_rsa():
    try:
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            data = file.read()
        elif 'data' in request.form:
            data = request.form['data'].encode()
        else:
            return jsonify({'error': 'No data provided'}), 400

        # Generate RSA keys
        rsa_key = RSA.generate(2048)
        public_key = base64.b64encode(rsa_key.publickey().export_key()).decode()
        private_key = base64.b64encode(rsa_key.export_key()).decode()

        # Generate AES key
        aes_key = get_random_bytes(16)
        
        # Encrypt data with AES
        encrypted_data = encrypt_data_with_aes(data, aes_key)

        # Encrypt AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        return jsonify({
            'ciphertext': base64.b64encode(encrypted_data).decode(),
            'aes_key': base64.b64encode(encrypted_aes_key).decode(),
            'public_key': public_key,
            'private_key': private_key
        })

    except Exception as e:
        print(f'Error en /encrypt_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_rsa', methods=['POST'])
def decrypt_rsa():
    try:
        data = request.get_json()
        if not all(k in data for k in ('ciphertext', 'private_key')):
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        ciphertext = base64.b64decode(data['ciphertext'])
        private_key = RSA.import_key(base64.b64decode(data['private_key']))

        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(ciphertext)

        return jsonify({'decrypted_data': decrypted_data.decode()}), 200

    except Exception as e:
        print(f'Error en /decrypt_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/encrypt_text_rsa', methods=['POST'])
def encrypt_text_rsa():
    try:
        data = request.get_json()
        if not data or 'plaintext' not in data:
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        plaintext = data.get('plaintext', '').encode()

        key = RSA.generate(2048)
        public_key = base64.b64encode(key.publickey().export_key()).decode()
        private_key = base64.b64encode(key.export_key()).decode()

        cipher_rsa = PKCS1_OAEP.new(key.publickey())
        ciphertext = cipher_rsa.encrypt(plaintext)

        response_data = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'public_key': public_key,
            'private_key': private_key
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f'Error en /encrypt_text_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decrypt_text_rsa', methods=['POST'])
def decrypt_text_rsa():
    try:
        data = request.get_json()
        if not all(k in data for k in ('ciphertext', 'private_key')):
            return jsonify({'error': 'Faltan datos en la solicitud'}), 400

        ciphertext = base64.b64decode(data['ciphertext'])
        private_key = RSA.import_key(base64.b64decode(data['private_key']))

        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(ciphertext)

        return jsonify({'decrypted_data': decrypted_data.decode()}), 200

    except Exception as e:
        print(f'Error en /decrypt_text_rsa: {e}', exc_info=True)  # Log detallado del error
        return jsonify({'error': 'Internal Server Error'}), 500

if __name__ == '__main__':
    app.run(port=5000)
