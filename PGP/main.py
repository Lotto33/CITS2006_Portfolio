from Encrypt_message import encrypt_and_sign
from Decrypt_message import decrypt_and_verify
from keyGen import generate_keys

def save_to_file(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)

def encrypt_flow():
    sender_priv = input("Enter path to your private key (e.g., jinhong_private.pem): ").strip()
    recipient_pub = input("Enter path to recipient's public key (e.g., jinhong_public.pem): ").strip()
    message = input("Enter the message you want to encrypt: ").strip()

    encrypted, signature = encrypt_and_sign(message, sender_priv, recipient_pub)
    combined = encrypted.decode() + "\n" + signature.decode()
    save_to_file("encrypted_message.txt", combined)
    print("Message encrypted and saved to 'encrypted_message.txt'")

def decrypt_flow():
    recipient_priv = input("Enter path to your private key (e.g., jinhong_private.pem): ").strip()
    sender_pub = input("Enter path to sender's public key (e.g., jinhong_public.pem): ").strip()
    enc_file = input("Enter path to encrypted message file (e.g., encrypted_message.txt): ").strip()

    decrypted_msg = decrypt_and_verify(enc_file, recipient_priv, sender_pub)
    if decrypted_msg:
        save_to_file("decrypted_message.txt", decrypted_msg)
        print("Message decrypted and saved to 'decrypted_message.txt'")

def keygen_flow():
    username = input("Enter a username for the key pair: ").strip()
    generate_keys(username)

def main():
    while True:
        print("\n PGP HELPER ONLINE")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Generate a new key pair")
        print("4. Exit")
        choice = input("Select option [1/2/3/4]: ").strip()

        if choice == "1":
            encrypt_flow()
        elif choice == "2":
            decrypt_flow()
        elif choice == "3":
            keygen_flow()
        elif choice == "4":
            print(" ___PGP PROMGRAM CLOSED___")
            break
        else:
            print("Invalid option. Please choose 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
