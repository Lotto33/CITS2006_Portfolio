from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64
import os

def load_key(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Key file not found at '{path}'. Please check the path and try again.")
        return None

def decrypt_and_verify(enc_file, recipient_private_path, sender_public_path):
    recipient_private_bytes = load_key(recipient_private_path)
    sender_public_bytes = load_key(sender_public_path)

    if not recipient_private_bytes or not sender_public_bytes:
        return

    try:
        recipient_private = serialization.load_pem_private_key(recipient_private_bytes, password=None)
        sender_public = serialization.load_pem_public_key(sender_public_bytes)
    except Exception as e:
        print(f"Error loading keys: {e}")
        return

    if not os.path.exists(enc_file):
        print(f"Error: Encrypted file '{enc_file}' not found.")
        return

    try:
        with open(enc_file, "rb") as f:
            lines = f.read().splitlines()
            if len(lines) < 2:
                print("Error: File must contain both encrypted message and signature.")
                return
            encrypted = base64.b64decode(lines[0])
            signature = base64.b64decode(lines[1])
    except Exception as e:
        print(f"Error reading or decoding the encrypted file: {e}")
        return

    try:
        decrypted = recipient_private.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    try:
        sender_public.verify(
            signature,
            decrypted,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Signature verified.")
    except InvalidSignature:
        print("Signature could not be verified!")

    print("Message:", decrypted.decode(errors='replace'))


