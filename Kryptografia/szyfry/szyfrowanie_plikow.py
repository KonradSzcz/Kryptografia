import base64
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import os

# Dostosowywanie klucza
def generate_key(key, length):
    key *= (length // len(key)) + 1
    return key[:length]

# Kompresja do base64
def file_to_base64_string(file_path):
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
            base64_encoded = base64.b64encode(file_content).decode('utf-8')
            return base64_encoded
    except Exception as e:
        raise ValueError(f"Błąd podczas konwersji pliku do Base64: {e}")

# Szyfrowanie DES
def encrypt_file_with_des(data, key):
    key = generate_key(key.encode('utf-8'), 8)
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data.encode('utf-8'), DES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

# Deszyfrowanie DES
def decrypt_file_with_des(encrypted_data, key):
    key = generate_key(key.encode('utf-8'), 8)
    iv = encrypted_data[:8]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    try:
        decrypted_padded_data = cipher.decrypt(encrypted_data[8:])
        return unpad(decrypted_padded_data, DES.block_size).decode('utf-8')
    except (ValueError, KeyError):
        return "Błędny klucz."

# Szyfrowanie AES
def encrypt_file_with_aes(data, key):
    key = generate_key(key.encode('utf-8'), 16)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

# Deszyfrowanie AES
def decrypt_file_with_aes(encrypted_data, key):
    key = generate_key(key.encode('utf-8'), 16)
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_padded_data = cipher.decrypt(encrypted_data[16:])
        return unpad(decrypted_padded_data, AES.block_size).decode('utf-8')
    except (ValueError, KeyError):
        return "Błędny klucz."
