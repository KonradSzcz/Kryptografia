import math

# Dostosowywanie klucza
def generate_key_sequence(key, length):
    key *= (length // len(key)) + 1
    return key[:length]

# Zmiana wartości znaków
def transform_char(char, factor):
    return chr((ord(char) + factor) % 256)

def mod_inverse(a, mod):
    try:
        return pow(a, -1, mod)
    except ValueError:
        return None

# Względnie piersze
def is_coprime(a, b):
    return math.gcd(a, b) == 1

def transposition_encrypt(plain_text, key):
    plain_text = plain_text.replace(" ", "")
    key_sequence = generate_key_sequence(key, len(plain_text))
    grid_size = len(key)

    # Tworzenie
    grid = [['' for _ in range(grid_size)] for _ in range((len(plain_text) + grid_size - 1) // grid_size)]
    index = 0

    # Wypełnianie
    for row in range(len(grid)):
        for col in range(grid_size):
            if index < len(plain_text):
                factor = (row + 1) * (col + 1)
                if is_coprime(factor, 256):
                    grid[row][col] = transform_char(plain_text[index], factor)
                else:
                    grid[row][col] = plain_text[index]
                index += 1

    # Szyfr
    ciphertext = []
    for diag in range(len(grid) + len(grid[0]) - 1):
        for row in range(len(grid)):
            col = diag - row
            if 0 <= col < len(grid[0]) and grid[row][col]:
                ciphertext.append(grid[row][col])

    return ''.join(ciphertext)

def transposition_decrypt(cipher_text, key):
    key_sequence = generate_key_sequence(key, len(cipher_text))
    grid_size = len(key)

    # Tworzenie
    grid_height = (len(cipher_text) + grid_size - 1) // grid_size
    grid = [['' for _ in range(grid_size)] for _ in range(grid_height)]

    # Wypełnianie
    index = 0
    for diag in range(len(grid) + len(grid[0]) - 1):
        for row in range(len(grid)):
            col = diag - row
            if 0 <= col < len(grid[0]) and index < len(cipher_text):
                grid[row][col] = cipher_text[index]
                index += 1

    # Jawny tekst
    plaintext = []
    for row in range(len(grid)):
        for col in range(len(grid[0])):
            if grid[row][col]:
                factor = (row + 1) * (col + 1)
                if is_coprime(factor, 256):
                    original_char = transform_char(grid[row][col], -factor)
                else:
                    original_char = grid[row][col]
                plaintext.append(original_char)

    return ''.join(plaintext)
