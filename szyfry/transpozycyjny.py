import math

# Dostosowywanie klucza
def generate_key(key, length):
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

# Funkcja tworzenia spirali
def create_spiral(size):
    spiral = [[0] * size for _ in range(size)]
    left, right, top, bottom = 0, size - 1, 0, size - 1
    num = 1

    while left <= right and top <= bottom:
        for i in range(left, right + 1):
            spiral[top][i] = num
            num += 1
        top += 1

        for i in range(top, bottom + 1):
            spiral[i][right] = num
            num += 1
        right -= 1

        for i in range(right, left - 1, -1):
            spiral[bottom][i] = num
            num += 1
        bottom -= 1

        for i in range(bottom, top - 1, -1):
            spiral[i][left] = num
            num += 1
        left += 1

    return spiral

def transposition_encrypt(plain_text, key):
    plain_text = plain_text.replace(" ", "")
    key_sequence = generate_key(key, len(plain_text))
    grid_size = len(key)

    # Tworzenie spirali
    spiral = create_spiral(grid_size)
    cipher_grid = [[None for _ in range(grid_size)] for _ in range(grid_size)]

    index = 0
    for i in range(grid_size):
        for j in range(grid_size):
            if spiral[i][j] is not None and index < len(plain_text):
                factor = spiral[i][j]
                if is_coprime(factor, 256):
                    cipher_grid[i][j] = transform_char(plain_text[index], factor)
                else:
                    cipher_grid[i][j] = plain_text[index]
                index += 1

    ciphertext = ''.join(''.join(cell for cell in row if cell is not None) for row in cipher_grid)
    return ciphertext

def transposition_decrypt(cipher_text, key):
    key_sequence = generate_key(key, len(cipher_text))
    grid_size = len(key)

    # Tworzenie spirali
    spiral = create_spiral(grid_size)
    cipher_grid = [[None for _ in range(grid_size)] for _ in range(grid_size)]

    index = 0
    for i in range(grid_size):
        for j in range(grid_size):
            if spiral[i][j] is not None and index < len(cipher_text):
                cipher_grid[i][j] = cipher_text[index]
                index += 1

    plaintext = []
    for i in range(grid_size):
        for j in range(grid_size):
            if cipher_grid[i][j] is not None:
                factor = spiral[i][j]
                if is_coprime(factor, 256):
                    original_char = transform_char(cipher_grid[i][j], -factor)
                else:
                    original_char = cipher_grid[i][j]
                plaintext.append(original_char)

    return ''.join(plaintext)
