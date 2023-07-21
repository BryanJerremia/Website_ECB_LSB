from flask import Flask, render_template, request, send_file, render_template_string
import base64
import os
from PIL import Image
import numpy as np
import io

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index_2.html')

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

'''
def xor_cypher_combined(plaintext, key):
    # Convert string to binary
    def string_to_binary(input_string):
        return ''.join(format(ord(c), '08b') for c in input_string)

    # Convert binary to string
    def binary_to_string(input_binary):
        return ''.join(chr(int(input_binary[i:i+8], 2)) for i in range(0, len(input_binary), 8))

    # XOR cypher
    def xor_cypher(input_binary, key):
        key_binary = string_to_binary(key)
        return ''.join(format(int(input_binary[i:i+8], 2) ^ int(key_binary[i%len(key_binary):i%len(key_binary)+8], 2), '08b') for i in range(0, len(input_binary), 8))

    # Encryption process
    plaintext_binary = string_to_binary(plaintext)
    ciphertext = xor_cypher(plaintext_binary, key)
    ciphertext_string = binary_to_string(ciphertext)

    return ciphertext_string
    '''

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

'''
@app.route('/encode', methods=['POST'])
def encode():
    image = request.files.get('image')
    secretMessage = request.form.get('secretMessage')
    # TODO: Implement encoding logic here
    return secretMessage

@app.route('/decode', methods=['POST'])
def decode():
    image = request.files.get('image')
    # TODO: Implement decoding logic here
    return "Decoded message"
'''
'''
@app.route('/encode', methods=['POST'])
def encode():
    image = request.files['image']
    secret_message = request.form['secretMessage']

    # Load the image
    img = Image.open(image)
    img_array = np.array(img)

    # Convert the secret message to binary
    secret_message += '[END]'
    secret_message = secret_message.encode('ascii')
    secret_message_bits = ''.join([format(i, '08b') for i in secret_message])

    # Flatten the image array
    img_array_flat = img_array.flatten()

    # Embed the secret message into the image
    for idx, bit in enumerate(secret_message_bits):
        val = img_array_flat[idx]
        val = bin(val)
        val = val[:-1] + bit
        img_array_flat[idx] = int(val, 2)

    # Reshape the image array
    img_array_encoded = img_array_flat.reshape(img_array.shape)

    # Save the encoded image
    encoded_image = Image.fromarray(img_array_encoded)
    encoded_image.save('encoded_image.png')

    return send_file('encoded_image.png', mimetype='image/png')

@app.route('/decode', methods=['POST'])
def decode():
    image = request.files['image']

    # Load the image
    img = Image.open(image)
    img_array = np.array(img)

    # Flatten the image array
    img_array_flat = img_array.flatten()

    # Extract the secret message from the image
    secret_message = ""
    idx = 0
    while secret_message[-5:] != '[END]':
        bits = [bin(i)[-1] for i in img_array_flat[idx:idx+8]]
        bits = ''.join(bits)
        secret_message += chr(int(bits, 2))
        idx += 8
        if idx > img_array_flat.shape[0]:
            return "TIDAK ADA PESAN RAHASIA"

    return secret_message[:-5]
'''

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
        img_encoded.save("encoded_image.png")
        return "Encoding berhasil. Gambar hasil encoding disimpan sebagai encoded_image.png"
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

# Contoh penggunaan
# encode_decode_lsb('gambar_contoh.png', 'Pesan rahasia')
# encode_decode_lsb('encoded_image.png')


@app.route('/encode', methods=['POST'])
def encode():
    image = request.files.get('image')
    secret_message = request.form.get('secretMessage')

    # Save the uploaded image
    image_path = 'uploaded_image.png'
    image.save(image_path)

    # Encode the secret message into the image
    result = encode_decode_lsb(image_path, secret_message)

    return result

@app.route('/decode', methods=['POST'])
def decode():
    image = request.files.get('image')

    # Save the uploaded image
    image_path = 'uploaded_image.png'
    image.save(image_path)

    # Decode the secret message from the image
    result = encode_decode_lsb(image_path)

    return result

if __name__ == '__main__':
    app.run(debug=True)

