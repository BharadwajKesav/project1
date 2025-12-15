from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(cipher.iv + ciphertext)

def decrypt_file(enc_file_path, key):
    with open(enc_file_path, 'rb') as enc_file:
        iv = enc_file.read(16)
        ciphertext = enc_file.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)