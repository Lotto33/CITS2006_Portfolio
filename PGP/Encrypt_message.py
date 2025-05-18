from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

def load_key(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Key file not found at '{path}'. Please check the path and try again.")
        return None

def encrypt_and_sign(message, sender_private_path, recipient_public_path):
    sender_private_bytes = load_key(sender_private_path)
    recipient_public_bytes = load_key(recipient_public_path)

    if not sender_private_bytes or not recipient_public_bytes:
        return None, None

    try:
        sender_private = serialization.load_pem_private_key(sender_private_bytes, password=None)
        recipient_public = serialization.load_pem_public_key(recipient_public_bytes)
    except Exception as e:
        print(f"Error loading keys: {e}")
        return None, None

    try:
        signature = sender_private.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        encrypted = recipient_public.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

        return base64.b64encode(encrypted), base64.b64encode(signature)

    except Exception as e:
        print(f"Error during encryption/signing: {e}")
        return None, None
