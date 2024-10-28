import base64
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, './szyfry')
from szyfry.polialfa import vigenere_decrypt, vigenere_encrypt
from szyfry.transpozycyjny import transposition_encrypt, transposition_decrypt
from szyfry.des import des_encrypt, des_decrypt
from szyfry.aes import aes_encrypt, aes_decrypt
from szyfry.szyfrowanie_plikow import encrypt_file_with_aes, decrypt_file_with_aes, encrypt_file_with_des, decrypt_file_with_des

# Polialfabetyczny
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

        if algorithm == 'aes':
            encrypted_data = encrypt_file_with_aes(base64_data, key)
        elif algorithm == 'des':
            encrypted_data = encrypt_file_with_des(base64_data, key)
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
root.geometry("1200x700")


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

decipher_frame = tk.LabelFrame(left_frame, text="Wybierz sposób odszyfrowania", font=("Arial", 14, "bold"), bg="#0abdb1")
decipher_frame.pack(pady=20, padx=10, fill="x")

poli_decrypt_button = ttk.Button(decipher_frame, text="Polialfabetyczny", command= decrypt_with_vigenere)
poli_decrypt_button.pack(pady=5, padx=10, fill="x")

transposition_decrypt_button = ttk.Button(decipher_frame, text="Transpozycyjny", command= decrypt_with_transposition)
transposition_decrypt_button.pack(pady=5, padx=10, fill="x")

des_decrypt_button = ttk.Button(decipher_frame, text="DES", command= decrypt_with_des)
des_decrypt_button.pack(pady=5, padx=10, fill="x")

aes_decrypt_button = ttk.Button(decipher_frame, text="AES", command=decrypt_with_aes)
aes_decrypt_button.pack(pady=5, padx=10, fill="x")

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

copy_button = ttk.Button(data_entry_frame,command=switch_text ,text="Skopiuj wynik")
copy_button.pack(padx=10, pady=10)

result_frame = tk.LabelFrame(center_frame, text="Wynik", font=("Arial", 12), bg="#56f2e1")
result_frame.pack(pady=20, padx=10, fill="both", expand=True)

cipher_text_output = tk.Label(result_frame, text="Tu się wyświetla", bg="#c9fef5", anchor="center")
cipher_text_output.pack(pady=10, padx=10, fill="both", expand=True)

# Prawy panel - Operacje na plikach
operations_frame = tk.LabelFrame(right_frame, text="Operacje na plikach", font=("Arial", 14, "bold"), bg="#0abdb1")
operations_frame.pack(pady=20, padx=10, fill="x")

file_button = ttk.Button(operations_frame,command=load_file ,text="Wczytaj tekst")
file_button.pack(pady=10, padx=10, fill="x")

file_encrypt_label = tk.Label(operations_frame, text="Szyfrowanie", font=("Arial", 12, "bold"), bg="#0abdb1")
file_encrypt_label.pack(anchor="center", pady=10)

file_encrypt_aes_button = ttk.Button(operations_frame, text="Szyfruj plik AES", command=encrypt_aes_handler)
file_encrypt_aes_button.pack(pady=5, padx=10, fill="x")

file_encrypt_des_button = ttk.Button(operations_frame, text="Szyfruj plik DES", command=encrypt_des_handler)
file_encrypt_des_button.pack(pady=5, padx=10, fill="x")

file_decrypt_label = tk.Label(operations_frame, text="Odszyfrowywanie", font=("Arial", 12, "bold"), bg="#0abdb1")
file_decrypt_label.pack(anchor="center", pady=10)

file_decrypt_aes_button = ttk.Button(operations_frame, text="Odszyfruj plik AES", command=decrypt_aes_handler)
file_decrypt_aes_button.pack(pady=5, padx=10, fill="x")

file_decrypt_des_button = ttk.Button(operations_frame, text="Odszyfruj plik DES", command=decrypt_des_handler)
file_decrypt_des_button.pack(pady=5, padx=10, fill="x")

# Główna pętla aplikacji
root.mainloop()
