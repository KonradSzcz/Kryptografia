from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# Dostosowywanie klucza
def generate_key(key):
    key *= (16 // len(key)) + 1
    return key[:16]


# Szyfrowanie
def aes_encrypt(plain_text, key):

    key_sequence = generate_key(key)

    cipher = AES.new(key_sequence.encode('utf-8'), AES.MODE_CBC)
    iv = cipher.iv
    cipher_text = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    return iv + cipher_text


# Deszyfrowanie
def aes_decrypt(cipher_text, key):

    key_sequence = generate_key(key)

    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = AES.new(key_sequence.encode('utf-8'), AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return plain_text.decode('utf-8')
