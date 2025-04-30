import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# === Helper function to derive a key from password and salt ===
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

# === Encryption ===
def encrypt_message():
    password = input("Enter password: ").encode()
    message = input("Enter message to encrypt: ").encode()
    salt = os.urandom(16)

    key = derive_key(password, salt)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message)

    # Save salt and encrypted message to a file
    with open("secret.dat", "wb") as f:
        f.write(salt + b"||" + encrypted)
    
    print("Message encrypted and saved to 'secret.dat'.")

# === Decryption ===
def decrypt_message():
    password = input("Enter password: ").encode()

    try:
        with open("secret.dat", "rb") as f:
            data = f.read()
            salt, encrypted = data.split(b"||")
    except Exception as e:
        print("Error reading file or wrong format:", e)
        return

    try:
        key = derive_key(password, salt)
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted)
        print("Decrypted message:", decrypted.decode())
    except Exception as e:
        print("Decryption failed:", e)

# === Main Menu ===
def main():
    while True:
        print("\n1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            encrypt_message()
        elif choice == '2':
            decrypt_message()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
