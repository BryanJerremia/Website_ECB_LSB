from flask import Flask, render_template, request, session, redirect, url_for, send_file
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
    result_encode = session.get('result_encode')
    result_decode = session.get('result_decode')
    action = session.get('action')
    session['result_encode'] = None
    session['result_decode'] = None
    result_encrypt = session.get('result_encrypt')
    result_decrypt = session.get('result_decrypt')
    action = session.get('action')
    session['result_encrypt'] = None
    session['result_decrypt'] = None
    result = session.get('result')
    action = session.get('action')
    return render_template('index.html', result_encrypt=result_encrypt, result_decrypt=result_decrypt,  result_encode=result_encode, result_decode=result_decode, result=result, action=action)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')
    encryptionKey = request.form.get('encryptionKey')
    # TODO: Implement encryption logic here
    ciphertext = xor_cypher_combined(plaintext, encryptionKey)
    session['result_encrypt'] = ciphertext
    session['result_decrypt'] = None
    return redirect(url_for('index'))


@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext')
    decryptionKey = request.form.get('decryptionKey')
    # TODO: Implement decryption logic here
    decrypted = xor_cypher_combined(ciphertext, decryptionKey, decrypt=True)
    session['result_encrypt'] = None
    session['result_decrypt'] = decrypted
    return redirect(url_for('index'))


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
    img = Image.open(image_path)
    width, height = img.size

    if message:
        # Encode
        message += '[END]'
        message = message.encode('ascii')
        message_bits = ''.join([format(i, '08b') for i in message])

        img = img.convert('RGB')
        pixels = img.load()

        data_index = 0
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]

                if data_index < len(message_bits):
                    r = (r & 0xFE) | int(message_bits[data_index])
                    data_index += 1
                if data_index < len(message_bits):
                    g = (g & 0xFE) | int(message_bits[data_index])
                    data_index += 1
                if data_index < len(message_bits):
                    b = (b & 0xFE) | int(message_bits[data_index])
                    data_index += 1

                pixels[x, y] = (r, g, b)

                if data_index >= len(message_bits):
                    break
            if data_index >= len(message_bits):
                break

        output_path = "static/gambar_hasil.png"
        img.save(output_path)
        return "Encoding berhasil. Gambar hasil encoding disimpan sebagai gambar_hasil.png"
    else:
        # Decode
        img = img.convert('RGB')
        pixels = img.load()

        message_bits = ""
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                message_bits += str(r & 1)
                message_bits += str(g & 1)
                message_bits += str(b & 1)

        message = ""
        data_index = 0
        while data_index < len(message_bits) - 7:
            bits = message_bits[data_index:data_index+8]
            byte = int(bits, 2)
            if byte == 0:
                break
            message += chr(byte)
            data_index += 8

        return message


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
