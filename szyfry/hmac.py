import hmac
import hashlib

def generate_hmac(data: bytes, key: bytes) -> str:

    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac(data: bytes, key: bytes, hmac_to_verify: str) -> bool:

    generated_hmac = generate_hmac(data, key)
    return hmac.compare_digest(generated_hmac, hmac_to_verify)
