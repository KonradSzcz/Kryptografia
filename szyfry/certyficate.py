# certificate_utils.py
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_certificate():
    """Wczytuje certyfikat `.crt` i zwraca jego szczegóły."""
    from tkinter import filedialog

    file_path = filedialog.askopenfilename(
        title="Wybierz plik certyfikatu (.crt)",
        filetypes=[("Certyfikaty", "*.crt")]
    )

    if not file_path:
        return None, "Nie wybrano pliku."

    try:
        # Odczytanie pliku certyfikatu
        with open(file_path, "rb") as cert_file:
            cert_data = cert_file.read()

        # Wczytanie certyfikatu w formacie PEM
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Pobranie szczegółów certyfikatu
        issuer = cert.issuer
        subject = cert.subject
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc
        serial_number = cert.serial_number
        signature_algorithm = cert.signature_algorithm_oid

        # Pobranie klucza publicznego i konwersja na format PEM
        public_key = cert.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        # Formatowanie szczegółów certyfikatu
        cert_info = f"""
        Wystawca: {issuer}
        Podmiot: {subject}
        Ważny od: {not_valid_before} UTC
        Ważny do: {not_valid_after} UTC
        Numer seryjny: {serial_number}
        Algorytm podpisu: {signature_algorithm._name}

        Klucz publiczny:
        {public_key_pem}
        """
        return cert, cert_info.strip(), None

    except Exception as e:
        return None, None, f"Błąd podczas wczytywania certyfikatu: {e}"

def display_certificate_nodes(cert):
    """Zwraca szczegółową hierarchię węzłów certyfikatu."""
    try:
        nodes = []

        # Issuer (Wystawca) - dodanie węzłów
        issuer = cert.issuer
        nodes.append("Wystawca:")
        for attribute in issuer:
            nodes.append(f"  {attribute.oid._name}: {attribute.value}")

        # Subject (Podmiot) - dodanie węzłów
        subject = cert.subject
        nodes.append("Podmiot:")
        for attribute in subject:
            nodes.append(f"  {attribute.oid._name}: {attribute.value}")

        # Opcjonalnie inne informacje o certyfikacie
        nodes.append(f"Numer seryjny: {cert.serial_number}")
        nodes.append(f"Algorytm podpisu: {cert.signature_algorithm_oid._name}")
        nodes.append(f"Ważny od: {cert.not_valid_before_utc}")
        nodes.append(f"Ważny do: {cert.not_valid_after_utc}")

        # Łączenie węzłów w jeden ciąg znaków
        return "\n".join(nodes)
    except Exception as e:
        return f"Błąd podczas wyświetlania węzłów certyfikatu: {e}"
