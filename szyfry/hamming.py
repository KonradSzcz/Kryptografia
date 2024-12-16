def calculate_parity_bits_length(data_length):
    r = 0
    while (2 ** r) < (data_length + r + 1):
        r += 1
    return r

def insert_parity_bits(data, r):
    data_with_parity = []
    j = 0
    for i in range(1, len(data) + r + 1):
        if i & (i - 1) == 0:
            data_with_parity.append(0)
        else:
            data_with_parity.append(int(data[j]))
            j += 1
    return data_with_parity

def set_parity_bits(data_with_parity, r):
    n = len(data_with_parity)
    for i in range(r):
        parity_index = (2 ** i) - 1
        parity = 0
        for j in range(1, n + 1):
            if j & (2 ** i) and j != (parity_index + 1):
                parity ^= data_with_parity[j - 1]
        data_with_parity[parity_index] = parity
    return data_with_parity

def encode_hamming(data):
    r = calculate_parity_bits_length(len(data))
    data_with_parity = insert_parity_bits(data, r)
    encoded_data = set_parity_bits(data_with_parity, r)
    return ''.join(map(str, encoded_data))

def detect_and_correct_error(received_data):
    n = len(received_data)
    r = calculate_parity_bits_length(n - calculate_parity_bits_length(n))
    error_position = 0
    for i in range(r):
        parity = 0
        for j in range(1, n + 1):
            if j & (2 ** i):
                parity ^= int(received_data[j - 1])
        if parity:
            error_position += 2 ** i
    if error_position != 0:
        received_data[error_position - 1] ^= 1
    corrected_data = []
    for i in range(1, n + 1):
        if i & (i - 1) != 0:
            corrected_data.append(received_data[i - 1])
    return ''.join(map(str, corrected_data))
