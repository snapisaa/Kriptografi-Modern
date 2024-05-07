from tkinter import *
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def generate_key(password):
    # Gunakan PBKDF2 untuk menghasilkan kunci dengan panjang yang sesuai
    salt = b'salt'  # Ganti dengan nilai salt yang unik
    return PBKDF2(password, salt, 16)  # 16 bytes untuk AES-128

def encrypt_text():
    key = generate_key(encryption_key_entry.get().encode())
    plaintext = plaintext_entry.get().encode()

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext))

    # Ubah cipherteks ke format base64 agar lebih mudah dibaca
    ciphertext_base64 = base64.b64encode(ciphertext)

    ciphertext_entry.delete(0, END)
    ciphertext_entry.insert(0, ciphertext_base64.decode())

def decrypt_text():
    key = generate_key(decryption_key_entry.get().encode())
    ciphertext_base64 = ciphertext_decrypt_entry.get()

    # Decode cipherteks dari base64
    ciphertext = base64.b64decode(ciphertext_base64)

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext).rstrip(b'\0')

    plaintext_decrypt_entry.delete(0, END)
    plaintext_decrypt_entry.insert(0, plaintext.decode())

def clear_entries():
    plaintext_entry.delete(0, END)
    encryption_key_entry.delete(0, END)
    ciphertext_entry.delete(0, END)

    ciphertext_decrypt_entry.delete(0, END)
    decryption_key_entry.delete(0, END)
    plaintext_decrypt_entry.delete(0, END)

# Create main window
root = Tk()
root.title("AES Encryption-Decryption")
root.configure(bg="#add8e6")  # Set background color to light blue

# Create frames
encryption_frame = LabelFrame(root, text="Encryption", bg="#add8e6")
encryption_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
decryption_frame = LabelFrame(root, text="Decryption", bg="#add8e6")
decryption_frame.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

# Encryption widgets
Label(encryption_frame, text="Plaintext:", bg="#add8e6").grid(row=0, column=0, padx=5, pady=2, sticky="w")
plaintext_entry = Entry(encryption_frame, width=40)
plaintext_entry.grid(row=0, column=1, padx=5, pady=2, columnspan=2)
Label(encryption_frame, text="Encryption Key:", bg="#add8e6").grid(row=1, column=0, padx=5, pady=2, sticky="w")
encryption_key_entry = Entry(encryption_frame, width=40)
encryption_key_entry.grid(row=1, column=1, padx=5, pady=2, columnspan=2)
encrypt_button = Button(encryption_frame, text="Encrypt", command=encrypt_text, bg="#4682b4", fg="white")  # Set button color
encrypt_button.grid(row=2, column=1, padx=5, pady=5, sticky="e")
Label(encryption_frame, text="Ciphertext:", bg="#add8e6").grid(row=3, column=0, padx=5, pady=2, sticky="w")
ciphertext_entry = Entry(encryption_frame, width=40)
ciphertext_entry.grid(row=3, column=1, padx=5, pady=2, columnspan=2)

# Decryption widgets
Label(decryption_frame, text="Ciphertext:", bg="#add8e6").grid(row=0, column=0, padx=5, pady=2, sticky="w")
ciphertext_decrypt_entry = Entry(decryption_frame, width=40)
ciphertext_decrypt_entry.grid(row=0, column=1, padx=5, pady=2, columnspan=2)
Label(decryption_frame, text="Decryption Key:", bg="#add8e6").grid(row=1, column=0, padx=5, pady=2, sticky="w")
decryption_key_entry = Entry(decryption_frame, width=40)
decryption_key_entry.grid(row=1, column=1, padx=5, pady=2, columnspan=2)
decrypt_button = Button(decryption_frame, text="Decrypt", command=decrypt_text, bg="#4682b4", fg="white")  # Set button color
decrypt_button.grid(row=2, column=1, padx=5, pady=5, sticky="e")
Label(decryption_frame, text="Plaintext:", bg="#add8e6").grid(row=3, column=0, padx=5, pady=2, sticky="w")
plaintext_decrypt_entry = Entry(decryption_frame, width=40)
plaintext_decrypt_entry.grid(row=3, column=1, padx=5, pady=2, columnspan=2)

# Clear button
clear_button = Button(root, text="Clear All", command=clear_entries, bg="#4682b4", fg="white")  # Set button color
clear_button.grid(row=1, column=0, columnspan=2, pady=10)

# Configure resizing behavior
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
encryption_frame.columnconfigure(1, weight=1)
decryption_frame.columnconfigure(1, weight=1)

# Run the application
root.mainloop()