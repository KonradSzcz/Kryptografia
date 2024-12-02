import base64
import os
import sys
import tkinter as tk
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter import ttk, filedialog, messagebox
import pyaudio
import wave
import threading
import keyboard

from szyfry.podpis import sign_file, verify_signature

sys.path.insert(0, './szyfry')
from szyfry.polialfa import vigenere_decrypt, vigenere_encrypt
from szyfry.transpozycyjny import transposition_encrypt, transposition_decrypt
from szyfry.des import des_encrypt, des_decrypt
from szyfry.aes import aes_encrypt, aes_decrypt
from szyfry.szyfrowanie_plikow import encrypt_file_with_aes, decrypt_file_with_aes, encrypt_file_with_des, \
    decrypt_file_with_des, encrypt_file_with_rsa, decrypt_file_with_rsa
from szyfry.rsa import RSAEncryption
from szyfry.audio import encrypt_audio_data, decrypt_audio_data
from szyfry.certyficate import load_certificate, display_certificate_nodes

# Utworzenie obiektu klasy RSAEncryption
rsa_encryption = RSAEncryption()


# Polialfabetycznyn
def encrypt_with_vigenere():
    plain_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if plain_text_value and key_value:
        cipher_text_result = vigenere_encrypt(plain_text_value, key_value)
        cipher_text_output.config(text=cipher_text_result)
    else:
        cipher_text_output.config(text="Podaj tekst jawny i klucz!")


def decrypt_with_vigenere():
    cipher_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if cipher_text_value and key_value:
        plain_text_result = vigenere_decrypt(cipher_text_value, key_value)
        cipher_text_output.config(text=plain_text_result)
    else:
        cipher_text_output.config(text="Podaj szyfr i klucz!")


# Transpozycyjny
def encrypt_with_transposition():
    plain_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if plain_text_value and key_value:
        cipher_text_result = transposition_encrypt(plain_text_value, key_value)
        cipher_text_output.config(text=cipher_text_result)
    else:
        cipher_text_output.config(text="Podaj tekst jawny i klucz!")


def decrypt_with_transposition():
    cipher_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if cipher_text_value and key_value:
        plain_text_result = transposition_decrypt(cipher_text_value, key_value)
        cipher_text_output.config(text=plain_text_result)
    else:
        cipher_text_output.config(text="Podaj szyfr i klucz!")


# DES
def encrypt_with_des():
    plain_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if plain_text_value and key_value:
        cipher_text_result = des_encrypt(plain_text_value, key_value)
        cipher_text_output.config(text=cipher_text_result)
    else:
        cipher_text_output.config(text="Podaj tekst jawny i klucz!")


def decrypt_with_des():
    cipher_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if cipher_text_value and key_value:
        try:
            plain_text_result = des_decrypt(cipher_text_value, key_value)
            cipher_text_output.config(text=plain_text_result)
        except ValueError:
            cipher_text_output.config(text="Błąd odszyfrowania!")


# AES
def encrypt_with_aes():
    plain_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if plain_text_value and key_value:
        cipher_text_result = aes_encrypt(plain_text_value, key_value)
        cipher_text_output.config(text=cipher_text_result.hex())
    else:
        cipher_text_output.config(text="Podaj tekst jawny i klucz!")


def decrypt_with_aes():
    cipher_text_value = plain_text.get("1.0", tk.END).strip()
    key_value = key_entry.get().strip()

    if cipher_text_value and key_value:
        try:
            plain_text_result = aes_decrypt(bytes.fromhex(cipher_text_value), key_value)
            cipher_text_output.config(text=plain_text_result)
        except ValueError:
            cipher_text_output.config(text="Błąd odszyfrowania!")


# RSA
def generate_rsa_keys():
    global public_key, private_key
    public_key, private_key = rsa_encryption.generate_keys()

    # Wyświetlanie kluczy w GUI (przykład)
    rsa_public_output.config(text=public_key.decode())
    rsa_private_output.config(text=private_key.decode())

    return public_key, private_key


def encrypt_with_rsa():
    plain_text_value = plain_text.get("1.0", tk.END).strip()
    public_key = rsa_public_output.cget("text").strip()

    if plain_text_value and public_key:
        cipher_text = rsa_encryption.rsa_encrypt(plain_text_value, public_key)
        cipher_text_output.config(text=cipher_text)
    else:
        cipher_text_output.config(text="Podaj tekst jawny i klucz publiczny!")


def decrypt_with_rsa():
    cipher_text_value = plain_text.get("1.0", tk.END).strip()
    private_key = rsa_private_output.cget("text").strip()

    if cipher_text_value and private_key:
        try:
            plain_text_result = rsa_encryption.rsa_decrypt(cipher_text_value, private_key)
            cipher_text_output.config(text=plain_text_result)
        except ValueError:
            cipher_text_output.config(text="Błąd odszyfrowania RSA!")
    else:
        cipher_text_output.config(text="Podaj szyfr i klucz prywatny!")


# Wybór plików
def select_file():
    file_path = filedialog.askopenfilename()
    return file_path


# Szyfrowanie plików
def encrypt_file(file_path, key, algorithm='aes'):
    try:
        with open(file_path, 'rb') as file:
            binary_data = file.read()

        base64_data = base64.b64encode(binary_data).decode('utf-8')

        # Dla AES, DES i RSA - szyfrowanie blokami
        if algorithm == 'aes':
            encrypted_data = encrypt_file_with_aes(base64_data, key)
        elif algorithm == 'des':
            encrypted_data = encrypt_file_with_des(base64_data, key)
        elif algorithm == 'rsa':
            encrypted_data = encrypt_file_with_rsa(base64_data, key)
        else:
            raise ValueError("Błąd algorytmu")

        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        cipher_text_output.config(text=f"Plik zapisany: {encrypted_file_path}")
    except Exception as e:
        cipher_text_output.config(text=f"Błąd podczas szyfrowania: {str(e)}")


# Odszyfrowywanie plików
def decrypt_file(encrypted_file_path, key, algorithm='aes'):
    try:
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        if algorithm == 'aes':
            decrypted_base64_data = decrypt_file_with_aes(encrypted_data, key)
        elif algorithm == 'des':
            decrypted_base64_data = decrypt_file_with_des(encrypted_data, key)
        elif algorithm == 'rsa':
            decrypted_data = decrypt_file_with_rsa(encrypted_data, key)
            if decrypted_data == "Błędny klucz.":
                return decrypted_data
        else:
            raise ValueError("Błąd algorytmu")

        if decrypted_base64_data == "Błędny klucz.":
            return decrypted_base64_data

        binary_data = base64.b64decode(decrypted_base64_data)

        original_file_path = encrypted_file_path.replace('.enc', '')
        with open(original_file_path, 'wb') as decrypted_file:
            decrypted_file.write(binary_data)

        cipher_text_output.config(text=f"Plik odszyfrowany: {original_file_path}")
    except ValueError as ve:
        cipher_text_output.config(text=str(ve))
    except Exception as e:
        cipher_text_output.config(text=f"Błąd podczas odszyfrowania: {str(e)}")


# Obsługa przycisków
def encrypt_aes_handler():
    file_path = select_file()
    key = key_entry.get()
    if file_path and key:
        encrypt_file(file_path, key, 'aes')
    else:
        cipher_text_output.config(text="Nie wybrano pliku lub nie podano klucza.")


def encrypt_des_handler():
    file_path = select_file()
    key = key_entry.get()
    if file_path and key:
        encrypt_file(file_path, key, 'des')
    else:
        cipher_text_output.config(text="Nie wybrano pliku lub nie podano klucza.")


def decrypt_aes_handler():
    file_path = select_file()
    key = key_entry.get()
    if file_path and key:
        result = decrypt_file(file_path, key, 'aes')
        if result == "Błędny klucz.":
            cipher_text_output.config(text=result)
        else:
            cipher_text_output.config(text="Plik odszyfrowany.")
    else:
        cipher_text_output.config(text="Nie wybrano pliku lub nie podano klucza.")


def decrypt_des_handler():
    file_path = select_file()
    key = key_entry.get()
    if file_path and key:
        result = decrypt_file(file_path, key, 'des')
        if result == "Błędny klucz.":
            cipher_text_output.config(text=result)
        else:
            cipher_text_output.config(text="Plik odszyfrowany.")
    else:
        cipher_text_output.config(text="Nie wybrano pliku lub nie podano klucza.")


# Funkcja szyfrowania RSA
def load_public_key_from_pem(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = RSA.import_key(key_file.read())
    return public_key


def load_private_key_from_pem(file_path):
    with open(file_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())
    return private_key


def encrypt_rsa_handler():
    file_path = select_file()
    public_key_path = filedialog.askopenfilename(title="Select RSA Public Key (.pem)",
                                                 filetypes=[("PEM files", "*.pem")])

    if file_path and public_key_path:
        try:
            public_key = load_public_key_from_pem(public_key_path)

            with open(file_path, 'rb') as file:
                binary_data = file.read()

            encrypted_data = encrypt_file_with_rsa(binary_data, public_key)

            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            cipher_text_output.config(text=f"Plik zapisany: {encrypted_file_path}")
        except Exception as e:
            cipher_text_output.config(text=f"Błąd podczas szyfrowania: {str(e)}")
    else:
        cipher_text_output.config(text="Nie wybrano pliku lub klucza publicznego.")


def decrypt_rsa_handler():
    file_path = select_file()
    private_key_path = filedialog.askopenfilename(title="Select RSA Private Key (.pem)",
                                                  filetypes=[("PEM files", "*.pem")])

    if file_path and private_key_path:
        try:
            private_key = load_private_key_from_pem(private_key_path)

            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            decrypted_data = decrypt_file_with_rsa(encrypted_data, private_key)

            original_file_path = file_path.replace('.enc', '')
            with open(original_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            cipher_text_output.config(text=f"Plik odszyfrowany: {original_file_path}")
        except Exception as e:
            cipher_text_output.config(text=f"Błąd podczas odszyfrowywania: {str(e)}")
    else:
        cipher_text_output.config(text="Nie wybrano pliku lub klucza prywatnego.")


# Algorytm Diffiego

def diffi():
    try:
        p, q = map(int, plain_text.get("1.0", tk.END).strip().split())
        a_private, b_private = map(int, key_entry.get().strip().split())

        print(f"Modulus (p): {p}")
        print(f"Podstawa (q): {q}")
        print(f"Prywatny klucz A: {a_private}")
        print(f"Prywatny klucz B: {b_private}")

        A_public = pow(q, a_private, p)
        B_public = pow(q, b_private, p)

        print(f"Publiczny klucz A (q^a mod p): {A_public}")
        print(f"Publiczny klucz B (q^b mod p): {B_public}")

        A_shared_secret = pow(B_public, a_private, p)
        B_shared_secret = pow(A_public, b_private, p)

        print(f"Wspólny klucz obliczany przez A (B^a mod p): {A_shared_secret}")
        print(f"Wspólny klucz obliczany przez B (A^b mod p): {B_shared_secret}")

        if A_shared_secret == B_shared_secret:
            result = f"\nWspólny klucz: {A_shared_secret}"
        else:
            result = "\nBłąd: Klucze publiczne się nie zgadzają!"

        cipher_text_output.config(text=result)

    except ValueError:
        messagebox.showerror("Błąd", "Proszę wprowadzić poprawne liczby w odpowiednich polach!")


# Funkcja nagrywania dźwięku
def record_audio():
    chunk = 1024
    format = pyaudio.paInt16
    channels = 1
    rate = 44100
    audio = pyaudio.PyAudio()

    stream = audio.open(format=format, channels=channels,
                        rate=rate, input=True,
                        frames_per_buffer=chunk)
    frames = []

    messagebox.showinfo("Nagrywanie", "Rozpoczynam nagrywanie. Wciśnij ESC, aby zakończyć.")

    recording = True

    def stop_recording(e):
        nonlocal recording
        recording = False

    keyboard.on_press_key("esc", stop_recording)

    try:
        while recording:
            data = stream.read(chunk)
            frames.append(data)
    except:
        pass

    keyboard.unhook_all()
    stream.stop_stream()
    stream.close()
    audio.terminate()

    audio_data = b''.join(frames)
    messagebox.showinfo("Nagrywanie zakończone", "Nagranie zakończone.")
    return audio_data


# Obsługa nagrywania i szyfrowania
def voice():
    audio_thread = threading.Thread(target=record_audio_threaded)
    audio_thread.start()


# Funkcja uruchamiająca nagrywanie i szyfrowanie w osobnym wątku
def record_audio_threaded():
    key = key_entry.get().strip()
    if not key:
        messagebox.showerror("Błąd", "Podaj klucz szyfrowania!")
        return

    audio_data = record_audio()  # Nagrywanie audio

    # Przekazanie zaszyfrowania audio
    encrypt_audio_data(audio_data, key, "encrypted_audio.wav")  # Szyfrowanie audio i zapisanie do pliku


# Odszyfrowanie audio
def decrypt_audio():
    key = key_entry.get().strip()  # Pobierz klucz szyfrowania
    if not key:
        messagebox.showerror("Błąd", "Podaj klucz szyfrowania!")
        return

    # Odszyfrowanie danych
    decrypt_audio_data("encrypted_audio.wav", key, "decrypted_audio.wav")  # Odszyfrowanie audio
    messagebox.showinfo("Odszyfrowanie zakończone", "Audio zostało odszyfrowane!")


def display_certificate():
    cert, cert_info, error = load_certificate()  # Wywołanie funkcji load_certificate z importu
    if error:
        messagebox.showerror("Błąd", error)
        return

    # Okno do wyświetlania szczegółów certyfikatu
    cert_window = tk.Toplevel(root)
    cert_window.title("Informacje o certyfikacie")
    cert_window.geometry("500x400")

    # Text widget do wyświetlania szczegółów certyfikatu
    text_widget = tk.Text(cert_window, wrap="word", font=("Arial", 10))
    text_widget.insert("1.0", cert_info)
    text_widget.config(state="disabled")  # Uniemożliwienie edycji
    text_widget.pack(expand=True, fill="both", padx=10, pady=10)

    # Wywołanie funkcji display_certificate_nodes i wyświetlenie hierarchii węzłów
    cert_nodes = display_certificate_nodes(cert)  # Wywołanie funkcji display_certificate_nodes
    nodes_window = tk.Toplevel(root)
    nodes_window.title("Hierarchia węzłów certyfikatu")
    nodes_window.geometry("500x400")

    # Text widget do wyświetlania węzłów
    nodes_text_widget = tk.Text(nodes_window, wrap="word", font=("Arial", 10))
    nodes_text_widget.insert("1.0", cert_nodes)
    nodes_text_widget.config(state="disabled")  # Uniemożliwienie edycji
    nodes_text_widget.pack(expand=True, fill="both", padx=10, pady=10)

    # Przycisk do zamknięcia okna z certyfikatem
    close_button = tk.Button(cert_window, text="Zamknij", command=cert_window.destroy)
    close_button.pack(pady=10)

    # Przycisk do zamknięcia okna z węzłami
    close_button_nodes = tk.Button(nodes_window, text="Zamknij", command=nodes_window.destroy)
    close_button_nodes.pack(pady=10)


# Funkcja podpisywania pliku
def sign_file_handler():
    file_to_sign = select_file()  # Wybór pliku do podpisania

    # Wybór klucza prywatnego
    private_file = filedialog.askopenfilename(title="Select Private Key (.pem)",
                                              filetypes=[("PEM files", "*.pem")])

    # Wywołanie funkcji podpisywania
    result = sign_file(private_file, file_to_sign)

    # Wyświetlenie wyniku w GUI
    cipher_text_output.config(text=result)


# Funkcja weryfikacji podpisu
def verify_signature_handler():
    file_to_verify = select_file()  # Wybór pliku do weryfikacji

    # Wybór klucza publicznego
    public_file = filedialog.askopenfilename(title="Select Public Key (.pem)",
                                             filetypes=[("PEM files", "*.pem")])

    # Wywołanie funkcji weryfikacji
    result = verify_signature(public_file, file_to_verify)

    # Wyświetlenie wyniku w GUI
    cipher_text_output.config(text=result)




# Dane z pliku
def load_file():
    file_path = select_file()
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                plain_text.delete("1.0", tk.END)
                plain_text.insert("1.0", content)
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie można wczytać pliku:\n{e}")


# Z dolu do gory
def switch_text():
    cipher_text_value = cipher_text_output.cget("text")
    plain_text.delete("1.0", tk.END)
    plain_text.insert("1.0", cipher_text_value)


# Inicjalizacja głównego okna
root = tk.Tk()
root.title("Lepsza Enigma")
root.geometry("1200x900")

# Ustawienie tytułu u góry
title_label = tk.Label(root, text="LEPSZA ENIGMA 3:0", font=("Arial", 24, "bold"), bg="#0abdb1", fg="black")
title_label.pack(fill="x")

# Tworzenie paneli
left_frame = tk.Frame(root, width=240, bg="#0abdb1")
left_frame.pack(side="left", fill="y")

center_frame = tk.Frame(root, width=720, bg="#56f2e1")
center_frame.pack(side="left", fill="both", expand=True)

right_frame = tk.Frame(root, width=240, bg="#0abdb1")
right_frame.pack(side="right", fill="y")

# Lewy panel - Wybierz szyfr i odszyfrowanie
cipher_frame = tk.LabelFrame(left_frame, text="Wybierz szyfr", font=("Arial", 14, "bold"), bg="#0abdb1")
cipher_frame.pack(pady=20, padx=10, fill="x")

poli_encrypt_button = ttk.Button(cipher_frame, text="Polialfabetyczny", command=encrypt_with_vigenere)
poli_encrypt_button.pack(pady=5, padx=10, fill="x")

transposition_encrypt_button = ttk.Button(cipher_frame, text="Transpozycyjny", command=encrypt_with_transposition)
transposition_encrypt_button.pack(pady=5, padx=10, fill="x")

des_encrypt_button = ttk.Button(cipher_frame, text="DES", command=encrypt_with_des)
des_encrypt_button.pack(pady=5, padx=10, fill="x")

aes_encrypt_button = ttk.Button(cipher_frame, text="AES", command=encrypt_with_aes)
aes_encrypt_button.pack(pady=5, padx=10, fill="x")

rsa_encrypt_button = ttk.Button(cipher_frame, text="RSA", command=encrypt_with_rsa)
rsa_encrypt_button.pack(pady=5, padx=10, fill="x")

decipher_frame = tk.LabelFrame(left_frame, text="Wybierz sposób odszyfrowania", font=("Arial", 14, "bold"),
                               bg="#0abdb1")
decipher_frame.pack(pady=20, padx=10, fill="x")

poli_decrypt_button = ttk.Button(decipher_frame, text="Polialfabetyczny", command=decrypt_with_vigenere)
poli_decrypt_button.pack(pady=5, padx=10, fill="x")

transposition_decrypt_button = ttk.Button(decipher_frame, text="Transpozycyjny", command=decrypt_with_transposition)
transposition_decrypt_button.pack(pady=5, padx=10, fill="x")

des_decrypt_button = ttk.Button(decipher_frame, text="DES", command=decrypt_with_des)
des_decrypt_button.pack(pady=5, padx=10, fill="x")

aes_decrypt_button = ttk.Button(decipher_frame, text="AES", command=decrypt_with_aes)
aes_decrypt_button.pack(pady=5, padx=10, fill="x")

rsa_decrypt_button = ttk.Button(decipher_frame, text="RSA", command=decrypt_with_rsa)
rsa_decrypt_button.pack(pady=5, padx=10, fill="x")

another_frame = tk.LabelFrame(left_frame, text="Pozostale opcje", font=("Arial", 14, "bold"),
                              bg="#0abdb1")
another_frame.pack(pady=20,padx=10, fill="x")

copy_button = ttk.Button(another_frame, command=switch_text, text="Skopiuj wynik")
copy_button.pack(padx=5, pady=10, fill="x")

rsa_key_button = ttk.Button(another_frame, command=generate_rsa_keys, text="Wygeneruj klucze RSA")
rsa_key_button.pack(padx=5, pady=10, fill="x")

diffi_button = ttk.Button(another_frame, command=diffi, text="Przyklad implementacji algorytmu Diffiego")
diffi_button.pack(padx=5, pady=10, fill="x")

voice_enc_button = ttk.Button(another_frame, command=voice, text="Nagraj i zaszyfruj wiadomość")
voice_enc_button.pack(padx=5, pady=10, fill="x")

voice_dec_button = ttk.Button(another_frame, command=decrypt_audio, text="Odszyfruj audio")
voice_dec_button.pack(padx=5, pady=10, fill="x")

cert_button = ttk.Button(another_frame, command=display_certificate, text="Wczytaj certyfikat")
cert_button.pack(padx=5, pady=10, fill="x")

sign_button = ttk.Button(another_frame, command=sign_file_handler, text="Podpisz plik")
sign_button.pack(padx=5, pady=10, fill="x")

verify_button = ttk.Button(another_frame, command=verify_signature_handler, text="Sprawdź podpis")
verify_button.pack(padx=5, pady=10, fill="x")

# Środkowy panel - Wprowadź dane i Wynik
data_entry_frame = tk.LabelFrame(center_frame, text="Wprowadź dane", font=("Arial", 12), bg="#56f2e1")
data_entry_frame.pack(pady=20, padx=10, fill="both", expand=True)

plain_text_label = tk.Label(data_entry_frame, text="Wiadomość do zaszyfrowania", bg="#56f2e1")
plain_text_label.pack(anchor="w", padx=10)

plain_text = tk.Text(data_entry_frame, height=5, bg="#c9fef5")
plain_text.pack(padx=10, pady=5, fill="x")

key_label = tk.Label(data_entry_frame, text="Klucz", bg="#56f2e1")
key_label.pack(anchor="w", padx=10)

key_entry = ttk.Entry(data_entry_frame)
key_entry.pack(padx=10, pady=5, fill="x")

rsa_public_frame = tk.LabelFrame(center_frame, text="Klucz RSA publiczny", font=("Arial", 12), bg="#56f2e1")
rsa_public_frame.pack(pady=10, padx=10, fill="both", expand=False)

rsa_public_output = tk.Label(rsa_public_frame, text="Publiczny", bg="#c9fef5", anchor="center", width=80, height=5,
                             font=("Arial", 10))
rsa_public_output.pack(pady=10, padx=10)

rsa_private_frame = tk.LabelFrame(center_frame, text="Klucz RSA prywatny", font=("Arial", 12), bg="#56f2e1")
rsa_private_frame.pack(pady=15, padx=10, fill="both", expand=False)

rsa_private_output = tk.Label(rsa_private_frame, text="Prywatny", bg="#c9fef5", anchor="center", width=80, height=5,
                              font=("Arial", 10))
rsa_private_output.pack(padx=10, pady=10)

result_frame = tk.LabelFrame(center_frame, text="Wynik", font=("Arial", 12), bg="#56f2e1")
result_frame.pack(pady=20, padx=10, fill="both", expand=False)

cipher_text_output = tk.Label(result_frame, text="Tu się wyświetla", bg="#c9fef5", anchor="center", width=80, height=5,
                              font=("Arial", 10))
cipher_text_output.pack(pady=10, padx=10)

# Prawy panel - Operacje na plikach
operations_frame = tk.LabelFrame(right_frame, text="Operacje na plikach", font=("Arial", 14, "bold"), bg="#0abdb1")
operations_frame.pack(pady=20, padx=10, fill="x")

file_button = ttk.Button(operations_frame, command=load_file, text="Wczytaj tekst")
file_button.pack(pady=10, padx=10, fill="x")

file_encrypt_label = tk.Label(operations_frame, text="Szyfrowanie", font=("Arial", 12, "bold"), bg="#0abdb1")
file_encrypt_label.pack(anchor="center", pady=10)

file_encrypt_aes_button = ttk.Button(operations_frame, text="Szyfruj plik AES", command=encrypt_aes_handler)
file_encrypt_aes_button.pack(pady=5, padx=10, fill="x")

file_encrypt_des_button = ttk.Button(operations_frame, text="Szyfruj plik DES", command=encrypt_des_handler)
file_encrypt_des_button.pack(pady=5, padx=10, fill="x")

file_encrypt_rsa_button = ttk.Button(operations_frame, text="Szyfruj plik RSA", command=encrypt_rsa_handler)
file_encrypt_rsa_button.pack(pady=5, padx=10, fill="x")

file_decrypt_label = tk.Label(operations_frame, text="Odszyfrowywanie", font=("Arial", 12, "bold"), bg="#0abdb1")
file_decrypt_label.pack(anchor="center", pady=10)

file_decrypt_aes_button = ttk.Button(operations_frame, text="Odszyfruj plik AES", command=decrypt_aes_handler)
file_decrypt_aes_button.pack(pady=5, padx=10, fill="x")

file_decrypt_des_button = ttk.Button(operations_frame, text="Odszyfruj plik DES", command=decrypt_des_handler)
file_decrypt_des_button.pack(pady=5, padx=10, fill="x")

file_decrypt_rsa_button = ttk.Button(operations_frame, text="Odszyfruj plik RSA", command=decrypt_rsa_handler)
file_decrypt_rsa_button.pack(pady=5, padx=10, fill="x")

# Główna pętla aplikacji
root.mainloop()
