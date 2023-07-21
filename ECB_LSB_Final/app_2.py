from flask import Flask, render_template, request, session, redirect, url_for
import base64
import os
from PIL import Image
import numpy as np
import io
import matplotlib.pyplot as plt


app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    result = session.get('result')
    action = session.get('action')
    return render_template('index.html', result=result, action=action)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')
    encryptionKey = request.form.get('encryptionKey')
    # TODO: Implement encryption logic here
    ciphertext = xor_cypher_combined(plaintext, encryptionKey)
    return ciphertext

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext')
    decryptionKey = request.form.get('decryptionKey')
    # TODO: Implement decryption logic here
    decrypted = xor_cypher_combined(ciphertext, decryptionKey, decrypt=True)
    return decrypted

def xor_cypher_combined(input_string, key, decrypt=False):
    # Convert string to binary
    input_binary = ''.join(format(ord(c), '08b') for c in input_string) if not decrypt else input_string

    # XOR cypher
    key_binary = ''.join(format(ord(c), '08b') for c in key)
    result = ''.join(format(int(input_binary[i:i+8], 2) ^ int(key_binary[i%len(key_binary):i%len(key_binary)+8], 2), '08b') for i in range(0, len(input_binary), 8))

    # Convert binary to string if decrypting
    if decrypt:
        result = ''.join(chr(int(result[i:i+8], 2)) for i in range(0, len(result), 8))

    return result

def encode_decode_lsb(image_path, message=None):
    img = np.asarray(Image.open(image_path))
    W, H = img.shape[:2]

    if message:
        # Encode
        message += '[END]'
        message = message.encode('ascii')
        message_bits = ''.join([format(i, '08b') for i in message])

        img = img.flatten()
        for idx, bit in enumerate(message_bits):
            val = img[idx]
            val = bin(val)
            val = val[:-1] + bit
            img[idx] = int(val, 2)
        img = img.reshape((W, H))

        img_encoded = Image.fromarray(img)
        img_encoded.save("static/gambar_hasil.png")

        return "Encoding berhasil. Gambar hasil encoding disimpan sebagai gambar_hasil.png"
    else:
        # Decode
        img = np.asarray(Image.open(image_path))
        img = img.flatten()
        msg = ""
        idx = 0
        while msg[-5:] != '[END]':
            bits = [bin(i)[-1] for i in img[idx:idx+8]]
            bits = ''.join(bits)
            msg += chr(int(bits, 2))
            idx += 8
            if idx > img.shape[0]:
                return "TIDAK ADA PESAN RAHASIA"

        return msg[:-5]

@app.route('/process', methods=['POST'])
def process():
    image = request.files['image']
    message = request.form['message']
    action = request.form['action']

    # Save the uploaded image
    image_path = 'uploaded_image.png'
    image.save(image_path)

    # Encode or decode the message
    if action == 'encode':
        result = encode_decode_lsb(image_path, message)
    else:
        result = encode_decode_lsb(image_path)

    session['result'] = result
    session['action'] = action
    return redirect(url_for('index'))

@app.route('/reset', methods=['POST'])
def reset():
    session.pop('result', None)
    session.pop('action', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
