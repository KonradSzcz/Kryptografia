import base64
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

# Funkcja szyfrowania pliku za pomocą RSA (dzielenie pliku na bloki)
def encrypt_file_with_rsa(data, public_key):
    try:
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_data = bytearray()

        # Dzielimy dane na mniejsze bloki, które mogą być zaszyfrowane przez RSA
        block_size = public_key.size_in_bytes() - 42  # 42 to rozmiar paddingu w PKCS1_OAEP
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            encrypted_block = cipher.encrypt(block)
            encrypted_data.extend(encrypted_block)

        return bytes(encrypted_data)

    except Exception as e:
        raise ValueError(f"Błąd podczas szyfrowania pliku: {e}")
# Funkcja deszyfrowania pliku za pomocą RSA (dzielenie pliku na bloki)
def decrypt_file_with_rsa(data, private_key):
    try:
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_data = bytearray()

        block_size = private_key.size_in_bytes()  # Maksymalny rozmiar bloku
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            decrypted_block = cipher.decrypt(block)
            decrypted_data.extend(decrypted_block)

        return bytes(decrypted_data)

    except Exception as e:
        raise ValueError(f"Błąd podczas odszyfrowywania pliku: {e}")



