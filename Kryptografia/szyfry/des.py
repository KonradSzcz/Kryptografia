from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

# Dostosowywanie klucza
def generate_key(key):
    key *= (8 // len(key)) + 1
    return key[:8]

# Szyfrowanie
def des_encrypt(plain_text, key):

    key_sequence = generate_key(key)

    cipher = DES.new(key_sequence.encode('utf-8'), DES.MODE_ECB)
    padded_text = pad(plain_text.encode('utf-8'), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode('utf-8')


# Deszyfrowanie
def des_decrypt(cipher_text, key):

    key_sequence = generate_key(key)

    cipher = DES.new(key_sequence.encode('utf-8'), DES.MODE_ECB)
    decoded_encrypted_text = base64.b64decode(cipher_text)
    decrypted_text = unpad(cipher.decrypt(decoded_encrypted_text), DES.block_size)
    return decrypted_text.decode('utf-8')
