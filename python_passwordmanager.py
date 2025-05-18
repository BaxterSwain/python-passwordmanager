import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self):
        self.key = None  # Fernet key used to encrypt/decrypt passwords
        self.password_file = None
        self.password_dict = {}  # In-memory store of site: password

    # --- Master Password-Based Encryption Functions ---

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        # Derive a strong encryption key from a master password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def create_key(self, path, master_password):
        # Generate a new Fernet key
        self.key = Fernet.generate_key()
        salt = os.urandom(16)  # Random salt for KDF
        derived_key = self._derive_key(master_password, salt)
        encrypted_key = Fernet(derived_key).encrypt(self.key)  # Encrypt the Fernet key

        with open(path, 'wb') as f:
            f.write(salt + encrypted_key)  # Save salt + encrypted Fernet key

    def load_key(self, path, master_password):
        # Load and decrypt the Fernet key using the master password
        with open(path, 'rb') as f:
            data = f.read()
            salt = data[:16]
            encrypted_key = data[16:]
            derived_key = self._derive_key(master_password, salt)
            self.key = Fernet(derived_key).decrypt(encrypted_key)

    # --- Password File Management ---

    def create_password_file(self, path, initial_values=None):
        self.password_file = path
        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_password(key, value)

    def load_password_file(self, path):
        self.password_file = path
        with open(path, 'r') as f:
            for line in f:
                site, encrypted = line.strip().split(":")
                self.password_dict[site] = Fernet(self.key).decrypt(encrypted.encode()).decode()

    # --- Core Functionality ---

    def add_password(self, site, password):
        if self.key is None:
            print("❌ Error: No encryption key loaded.")
            return

        self.password_dict[site] = password
        if self.password_file is not None:
            with open(self.password_file, 'a+') as f:
                encrypted = Fernet(self.key).encrypt(password.encode())
                f.write(site + ":" + encrypted.decode() + "\n")

    def get_password(self, site):
        return self.password_dict.get(site, "❌ No password found for this site.")


# --- CLI Interface ---
def main():
    default_passwords = {
        "email": "1234567",
        "facebook": "myfbpassword",
        "youtube": "myytpassword",
        "something": "myotherpassword",
    }

    pm = PasswordManager()

    print("""
What do you want to do?
1. Create a new key
2. Load an existing key
3. Create a new password file
4. Load an existing password file
5. Add a new password
6. Get a password
q. Exit
""")

    done = False

    while not done:
        user_choice = input("Enter your choice: ")

        if user_choice == "1":
            path = input("Enter the path to save the key: ")
            master = input("Enter a master password: ")
            pm.create_key(path, master)
            print(f"Key created and saved to {path}")

        elif user_choice == "2":
            path = input("Enter the path to load the key: ")
            master = input("Enter your master password: ")
            try:
                pm.load_key(path, master)
                print(f"Key loaded from {path}")
            except:
                print("❌ Failed to load key. Wrong password or corrupt file.")

        elif user_choice == "3":
            if pm.key is None:
                print("❌ Please load or create a key first.")
                continue
            path = input("Enter the path to save the password file: ")
            pm.create_password_file(path, default_passwords)
            print(f"Password file created at {path}")

        elif user_choice == "4":
            if pm.key is None:
                print("❌ Please load or create a key first.")
                continue
            path = input("Enter the path to load the password file: ")
            pm.load_password_file(path)
            print(f"Password file loaded from {path}")

        elif user_choice == "5":
            if pm.key is None:
                print("❌ Please load or create a key first.")
                continue
            site = input("Enter the site name: ")
            password = input("Enter the password: ")
            pm.add_password(site, password)
            print(f"Password for {site} added.")

        elif user_choice == "6":
            site = input("Enter the site name: ")
            password = pm.get_password(site)
            print(f"Password for {site} is {password}")

        elif user_choice == "q":
            done = True
            print("Goodbye!")

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
