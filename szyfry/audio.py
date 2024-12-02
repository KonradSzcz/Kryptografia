import wave
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Funkcja do zapisania audio w formacie WAV
def save_audio_as_wav(audio_data, output_file):
    # Załóżmy, że audio_data jest w formacie bytes i jest dźwiękiem mono (1 kanał, 16-bitowy)
    num_channels = 1
    sample_width = 2  # 16-bitowe próbki (2 bajty na próbkę)
    framerate = 44100  # Częstotliwość próbkowania (np. 44.1 kHz)
    num_frames = len(audio_data) // (num_channels * sample_width)  # Liczba ramek

    comp_type = 'NONE'  # Brak kompresji
    comp_name = 'not compressed'  # Typ kompresji

    # Tworzenie pliku WAV
    try:
        with wave.open(output_file, 'wb') as wav_file:
            wav_file.setnchannels(num_channels)
            wav_file.setsampwidth(sample_width)
            wav_file.setframerate(framerate)
            wav_file.setnframes(num_frames)
            wav_file.setcomptype(comp_type, comp_name)

            # Zapisanie danych audio
            wav_file.writeframes(audio_data)
            print(f"Zapisano dane audio do pliku WAV: {output_file}")
    except Exception as e:
        print(f"Błąd zapisu pliku WAV: {e}")

# Funkcja szyfrująca dane audio przy użyciu AES
def encrypt_audio_data(audio_data, key, output_file):
    key = generate_key(key, 16)  # Dopasowanie klucza do 16 bajtów
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)

    # Zapisanie danych audio jako plik WAV
    temp_input_file = "temp_audio.wav"
    save_audio_as_wav(audio_data, temp_input_file)

    # Szyfrowanie danych
    with open(temp_input_file, 'rb') as f:
        audio_data = f.read()

    # Padding danych
    padded_data = pad(audio_data, AES.block_size)

    # Szyfrowanie
    iv = cipher.iv
    encrypted_data = cipher.encrypt(padded_data)

    # Zapisanie zaszyfrowanych danych do pliku
    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)  # Zapisujemy IV i dane

    print(f"Zaszyfrowano dane audio i zapisano w pliku: {output_file}")
    os.remove(temp_input_file)  # Usuwamy tymczasowy plik WAV

# Funkcja do odszyfrowania danych audio
def decrypt_audio_data(encrypted_file_path, key, output_file):
    try:
        # Odczytanie zaszyfrowanych danych
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        # Wyciąganie IV (pierwsze 16 bajtów)
        iv = encrypted_data[:16]
        encrypted_audio = encrypted_data[16:]

        # Odszyfrowanie
        decrypted_audio = decrypt_with_aes(encrypted_audio, key, iv)

        # Zapisanie odszyfrowanych danych audio
        with open(output_file, "wb") as f:
            f.write(decrypted_audio)

        print(f"Odszyfrowano i zapisano do pliku: {output_file}")

    except Exception as e:
        print(f"Błąd odszyfrowywania: {e}")

# Funkcja odszyfrowująca z AES
def decrypt_with_aes(encrypted_data, key, iv):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)

    try:
        # Odszyfrowanie i usunięcie paddingu
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded_data, AES.block_size)

    except (ValueError, KeyError):
        return "Błąd podczas odszyfrowywania."

# Dostosowanie klucza
def generate_key(key, length):
    key *= (length // len(key)) + 1
    return key[:length]