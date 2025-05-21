from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

def format_key(key_str: str) -> bytes:
    key = key_str.encode('utf-8')
    if len(key) <= 16:
        key += b' ' * (16 - len(key))
    elif len(key) <= 24:
        key += b' ' * (24 - len(key))
    elif len(key) <= 32:
        key += b' ' * (32 - len(key))
    else:
        key = key[:32]
    return key

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        key = request.form['key']
        action = request.form['action']
        file = request.files['file']

        if not key or not file:
            return "Vui lòng nhập khóa và chọn file!"

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            data = f.read()

        key_bytes = format_key(key)

        if action == 'encrypt':
            cipher = AES.new(key_bytes, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            result = cipher.iv + ct_bytes
            result_filename = f'encrypted_{filename}'
        elif action == 'decrypt':
            iv = data[:16]
            ct = data[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            try:
                result = unpad(cipher.decrypt(ct), AES.block_size)
            except ValueError:
                return "Sai khóa hoặc dữ liệu bị lỗi!"
            result_filename = f'decrypted_{filename}'
        else:
            return "Hành động không hợp lệ"

        result_path = os.path.join(RESULT_FOLDER, result_filename)
        with open(result_path, 'wb') as f:
            f.write(result)

        return send_file(result_path, as_attachment=True)

    return render_template('index.html')
