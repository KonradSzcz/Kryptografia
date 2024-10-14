# Szyfrowanie
def vigenere_encrypt(plain_text, key):
    cipher_text = []
    key = key.upper()
    key_len = len(key)
    key_index = 0

    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            if char.islower():
                cipher_text.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            elif char.isupper():
                cipher_text.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            key_index = (key_index + 1) % key_len
        else:
            cipher_text.append(char)

    return ''.join(cipher_text)

# Deszyfracja
def vigenere_decrypt(cipher_text, key):
    plain_text = []
    key = key.upper()
    key_len = len(key)
    key_index = 0

    for char in cipher_text:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            if char.islower():
                plain_text.append(chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a')))
            elif char.isupper():
                plain_text.append(chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A')))
            key_index = (key_index + 1) % key_len
        else:
            plain_text.append(char)

    return ''.join(plain_text)
