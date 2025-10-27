import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

def private_pem_to_key(priv_pem: str):
    return serialization.load_pem_private_key(priv_pem.encode(), password=None)

def pub_numbers_from_private_pem(priv_pem: str):
    priv = private_pem_to_key(priv_pem)
    pub = priv.public_key().public_numbers()
    return pub.n, pub.e

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url(n.to_bytes(length, "big"))

def jwk_from_private_pem(priv_pem: str, kid: int):
    n, e = pub_numbers_from_private_pem(priv_pem)
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": str(kid),
            "n": int_to_b64url(n), "e": int_to_b64url(e)}
