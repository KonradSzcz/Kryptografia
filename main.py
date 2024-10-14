import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sys

sys.path.insert(0, '/szyfry/polialfa.py')
from szyfry.polialfa import vigenere_decrypt, vigenere_encrypt

sys.path.insert(0, '/szyfry/transpozycyjny.py')
from szyfry.transpozycyjny import transposition_encrypt, transposition_decrypt


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


# Dane z pliku
def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
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



root = tk.Tk()
root.title("Cipher Application")

# Rozmiar okna
root.geometry("800x600")

cipher_frame = ttk.LabelFrame(root, text="Wybierz szyfr")
cipher_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nw")

decipher_frame = ttk.LabelFrame(root, text="Wybierz sposób odszyfrowania")
decipher_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nw")

text_frame = ttk.LabelFrame(root, text="Wprowadź dane")
text_frame.grid(row=0, column=1, padx=10, pady=10)

cipher_output_frame = ttk.LabelFrame(root, text="Wynik")
cipher_output_frame.grid(row=2, column=1, padx=10, pady=10)

# Rozmiar przycisku
button_width = 20

# Przyciski szyfrowania
cipher_button = ttk.Button(cipher_frame, text="Polialfabetyczny", command=encrypt_with_vigenere, width=button_width)
cipher_button.grid(row=0, column=0, padx=5, pady=5)

transposition_button = ttk.Button(cipher_frame, text="Transpozycyjny", command=encrypt_with_transposition,
                                  width=button_width)
transposition_button.grid(row=1, column=0, padx=5, pady=5)

# Przyciski odszyfrowywania
decrypt_button = ttk.Button(decipher_frame, text="Polialfabetyczny", command=decrypt_with_vigenere, width=button_width)
decrypt_button.grid(row=0, column=0, padx=5, pady=5)

decrypt_transposition_button = ttk.Button(decipher_frame, text="Transpozycyjny", command=decrypt_with_transposition,
                                          width=button_width)
decrypt_transposition_button.grid(row=1, column=0, padx=5, pady=5)

# Przycisk wczytania z pliku i switcha
load_button = ttk.Button(text_frame, text="Wczytaj tekst z pliku", command=load_file)
load_button.grid(row=3, column=0, padx=10, pady=5)

copy_button = ttk.Button(text_frame, text="Skopiuj wynik", command=switch_text, width=button_width)
copy_button.grid(row=4, column=0, padx=10, pady=5)

# Pole tekstowe
plain_text = tk.Text(text_frame, height=5, width=40)
plain_text.grid(row=0, column=0, padx=10, pady=10)

# Klucz
key_label = ttk.Label(text_frame, text="Klucz:")
key_label.grid(row=1, column=0, sticky="w", padx=10)

key_entry = ttk.Entry(text_frame, width=40)
key_entry.grid(row=2, column=0, padx=10, pady=5)

# Pole wynikowe
cipher_text_label = ttk.Label(cipher_output_frame, text="Tu się wyświetla")
cipher_text_label.grid(row=0, column=0, padx=10, pady=10)

cipher_text_output = tk.Label(cipher_output_frame, height=5, width=40, relief="sunken", anchor="w")
cipher_text_output.grid(row=1, column=0, padx=10, pady=10)

root.mainloop()
