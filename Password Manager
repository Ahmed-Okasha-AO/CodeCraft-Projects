# Made By Ahmed Okasha

import os
import json
import base64
import hashlib
from tkinter import *
from tkinter import messagebox, simpledialog
from tkinter import font as tkFont
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import string

# Constants
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
VAULT_FILE = 'vault.enc'
PASSWORD_HASH_FILE = 'master_password.hash'

# Derive a key using PBKDF2HMAC from the master password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt data using AES
def encrypt_data(data, key):
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(nonce + encryptor.tag + encrypted_data).decode()

# Decrypt data using AES
def decrypt_data(encrypted_data, key):
    try:
        data = base64.urlsafe_b64decode(encrypted_data.encode())
        nonce, tag, encrypted_data = data[:NONCE_SIZE], data[NONCE_SIZE:NONCE_SIZE+16], data[NONCE_SIZE+16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        return None

# Save the entire encrypted vault
def save_vault(vault, key):
    encrypted_vault = encrypt_data(json.dumps(vault), key)
    with open(VAULT_FILE, 'w') as file:
        file.write(encrypted_vault)

# Load and decrypt the vault
def load_vault(key):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, 'r') as file:
        encrypted_vault = file.read()
    decrypted_vault = decrypt_data(encrypted_vault, key)
    return json.loads(decrypted_vault) if decrypted_vault else {}

# Generate a random password
def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Hash and store the master password
def store_master_password_hash(master_password):
    salt = os.urandom(SALT_SIZE)
    hashed_password = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    with open(PASSWORD_HASH_FILE, 'wb') as file:
        file.write(salt + hashed_password)

# Verify the master password
def verify_master_password(master_password):
    if not os.path.exists(PASSWORD_HASH_FILE):
        return False
    with open(PASSWORD_HASH_FILE, 'rb') as file:
        data = file.read()
    salt, stored_hash = data[:SALT_SIZE], data[SALT_SIZE:]
    hashed_password = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return hashed_password == stored_hash

# GUI Application
class PasswordManagerGUI:
    def __init__(self, root):
        self.master_password = None
        self.key = None
        self.vault = None

        self.root = root
        self.root.title("Futuristic Password Manager")
        self.root.geometry("1000x700")
        self.root.attributes('-fullscreen', True)
        self.root.configure(bg='#0f0f0f')  # Dark futuristic background

        self.title_font = tkFont.Font(family="Orbitron", size=24, weight="bold")
        self.button_font = tkFont.Font(family="Orbitron", size=16)

        # Neon Title Label
        self.label = Label(root, text="Enter Master Password", font=self.title_font, fg='#0effa3', bg='#0f0f0f')
        self.label.pack(pady=40)

        self.password_entry = Entry(root, show="*", font=self.button_font, bg='#1f1f1f', fg='#ffffff', insertbackground='#ffffff', relief=FLAT)
        self.password_entry.pack(pady=20, ipadx=10, ipady=10)

        # Neon Login Button
        self.login_button = Button(root, text="Login", font=self.button_font, command=self.login, bg="#00ff85", fg="white", activebackground="#00d672", relief=FLAT)
        self.login_button.pack(pady=20, ipadx=30, ipady=10)

        # Neon Exit Button
        self.exit_button = Button(root, text="Exit", font=self.button_font, command=root.quit, bg="#ff5555", fg="white", activebackground="#ff2222", relief=FLAT)
        self.exit_button.pack(pady=20, ipadx=30, ipady=10)

    def login(self):
        master_password = self.password_entry.get()

        if os.path.exists(PASSWORD_HASH_FILE):
            if verify_master_password(master_password):
                salt = os.urandom(SALT_SIZE)
                self.key = derive_key(master_password, salt)
                self.vault = load_vault(self.key)
                self.load_password_manager_ui()
            else:
                messagebox.showerror("Error", "Invalid master password.")
        else:
            # If no password hash exists, create a new one
            store_master_password_hash(master_password)
            messagebox.showinfo("Success", "Master password set successfully.")
            salt = os.urandom(SALT_SIZE)
            self.key = derive_key(master_password, salt)
            self.vault = {}
            self.load_password_manager_ui()

    def load_password_manager_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Neon Title
        self.label = Label(self.root, text="Password Manager", font=self.title_font, fg='#0effa3', bg='#0f0f0f')
        self.label.pack(pady=40)

        # Neon Add Password Button
        self.add_button = Button(self.root, text="Add Password", font=self.button_font, command=self.add_password, bg="#1f8fff", fg="white", activebackground="#0077ff", relief=FLAT)
        self.add_button.pack(pady=20, ipadx=30, ipady=10)

        # Neon Retrieve Password Button
        self.retrieve_button = Button(self.root, text="Retrieve Password", font=self.button_font, command=self.retrieve_password, bg="#ff7f50", fg="white", activebackground="#ff5733", relief=FLAT)
        self.retrieve_button.pack(pady=20, ipadx=30, ipady=10)

        # Neon Generate Password Button
        self.generate_button = Button(self.root, text="Generate Password", font=self.button_font, command=self.generate_password, bg="#8BC34A", fg="white", activebackground="#66bb6a", relief=FLAT)
        self.generate_button.pack(pady=20, ipadx=30, ipady=10)

        # Neon Exit Button
        self.exit_button = Button(self.root, text="Exit", font=self.button_font, command=self.root.quit, bg="#ff5555", fg="white", activebackground="#ff2222", relief=FLAT)
        self.exit_button.pack(pady=20, ipadx=30, ipady=10)

    def add_password(self):
        website = simpledialog.askstring("Input", "Enter the website:")
        password = simpledialog.askstring("Input", "Enter the password:")
        encrypted_password = encrypt_data(password, self.key)
        self.vault[website] = encrypted_password
        save_vault(self.vault, self.key)

    def retrieve_password(self):
        website = simpledialog.askstring("Input", "Enter the website:")
        if website in self.vault:
            encrypted_password = self.vault[website]
            password = decrypt_data(encrypted_password, self.key)
            if password:
                messagebox.showinfo("Password", f"Password for {website}: {password.decode()}")
            else:
                messagebox.showerror("Error", "Failed to decrypt password.")
        else:
            messagebox.showerror("Error", f"No password found for {website}.")

    def generate_password(self):
        length = simpledialog.askinteger("Input", "Enter the password length:")
        generated_password = generate_password(length)
        messagebox.showinfo("Generated Password", f"Generated password: {generated_password}")

if __name__ == '__main__':
    root = Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
