from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSAEncryption:
    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Zapisz klucze do plików PEM
        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key)
        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(private_key)

        print("Klucze RSA wygenerowane i zapisane jako public_key.pem i private_key.pem")
        return public_key, private_key

    def rsa_encrypt(self, message, public_key_pem):
        try:
            # Upewnij się, że public_key_pem jest w formacie PEM
            public_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_message = cipher.encrypt(message.encode())
            return base64.b64encode(encrypted_message).decode('utf-8')
        except Exception as e:
            return f"Błąd szyfrowania: {str(e)}"

    def rsa_decrypt(self, encrypted_message, private_key_pem):
        try:
            private_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_OAEP.new(private_key)
            encrypted_message = base64.b64decode(encrypted_message)
            decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
            return decrypted_message
        except Exception as e:
            return f"Błąd odszyfrowywania: {str(e)}"
