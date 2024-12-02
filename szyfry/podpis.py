from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa

# Funkcja podpisywania
def sign_file(private_file, file_to_sign):
    try:
        # Wczytaj klucz prywatny
        with open(private_file, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)

        # Wczytaj plik do podpisania
        with open(file_to_sign, "rb") as f:
            file_data = f.read()

        # Tworzenie podpisu
        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Zapis podpisu do pliku
        with open(file_to_sign, "wb") as f:
            f.write(file_data)
            f.write(b"---SIGNATURE---")  # Separator
            f.write(signature)

        return "Podpis został dodany do pliku."
    except Exception as e:
        return f"Błąd podczas podpisywania pliku: {e}"

# Funkcja weryfikacji podpisu
def verify_signature(public_file, file_to_verify):
    try:
        # Wczytaj klucz publiczny
        with open(public_file, "rb") as f:
            public_key = load_pem_public_key(f.read())

        # Wczytaj plik do weryfikacji
        with open(file_to_verify, "rb") as f:
            file_content = f.read()

        file_data, _, signature = file_content.rpartition(b"---SIGNATURE---")

        # Weryfikacja podpisu
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return "Podpis jest prawidłowy."
    except Exception as e:
        return f"Podpis nie jest prawidłowy: {e}"
