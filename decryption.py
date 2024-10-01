import tkinter as tk
from tkinter import ttk, messagebox
import csv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

# RC4 functions
def rc4_initialize(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_generate_keystream(S, length):
    i = j = 0
    key_stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key_stream.append(S[(S[i] + S[j]) % 256])
    return key_stream

# ChaCha20 keystream generation
def generate_keystream_chacha20(key, nonce, length):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b'\x00' * length)

# XOR function
def xor_with_keystream(ciphertext, keystream):
    return bytes([c ^ k for c, k in zip(ciphertext, keystream)])

# Save to CSV with UTF-8 encoding
def save_to_csv(data, filename):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

# Decrypt function
def decrypt():
    cipher_type = cipher_type_var.get()
    algo = algo_var.get()
    
    try:
        with open("cipher_text.csv", mode='r') as file:
            reader = csv.reader(file)
            ciphertext = bytes([int(value) for row in reader for value in row])
    except FileNotFoundError:
        messagebox.showerror("File Error", "cipher_text.csv not found. Please provide the ciphertext file.")
        return

    ciphertext_size = len(ciphertext)

    if cipher_type == "Stream":
        filename = "RC4_A5.csv" if algo == "RC4" else "ChaCha_A5.csv"
        keystream = []
        try:
            with open(filename, mode='r') as file:
                reader = csv.reader(file)
                for row in reader:
                    keystream.extend([int(value) for value in row])
        except FileNotFoundError:
            messagebox.showerror("File Error", f"{filename} not found. Generate the key stream first.")
            return
        
        if len(keystream) < ciphertext_size:
            messagebox.showerror("Size Error", "Keystream is shorter than the ciphertext size.")
            return
        
        plaintext_bytes = xor_with_keystream(ciphertext, keystream[:ciphertext_size])
        plaintext = plaintext_bytes.decode('utf-8', errors='replace')
        save_to_csv([c for c in plaintext], "plain_text.csv")
        messagebox.showinfo("Success", "Plaintext is saved to plain_text.csv.")
    else:
        messagebox.showinfo("Info", "Decryption is only available for stream ciphers.")

# Update algorithm options based on cipher type
def update_algo_options(event):
    cipher_type = cipher_type_var.get()
    if (cipher_type == "Stream"):
        algo_var.set("RC4")
        algo_menu['values'] = ["RC4", "ChaCha20"]
    elif (cipher_type == "Block"):
        algo_var.set("AES")
        algo_menu['values'] = ["AES", "DES"]

# GUI setup
root = tk.Tk()
root.title("Decryption")

tk.Label(root, text="Select Cipher Type:").grid(row=0, column=0, padx=10, pady=10)
cipher_type_var = tk.StringVar()
cipher_type_menu = ttk.Combobox(root, textvariable=cipher_type_var)
cipher_type_menu['values'] = ["Stream", "Block"]
cipher_type_menu.grid(row=0, column=1, padx=10, pady=10)
cipher_type_menu.bind("<<ComboboxSelected>>", update_algo_options)

tk.Label(root, text="Select Algorithm:").grid(row=1, column=0, padx=10, pady=10)
algo_var = tk.StringVar()
algo_menu = ttk.Combobox(root, textvariable=algo_var)
algo_menu.grid(row=1, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=2, columnspan=2, padx=10, pady=10)

root.mainloop()
