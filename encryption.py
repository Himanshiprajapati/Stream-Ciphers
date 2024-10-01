import tkinter as tk
from tkinter import ttk, messagebox
import csv

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

def xor_with_keystream(data, keystream):
    return [d ^ k for d, k in zip(data, keystream)]

def save_to_csv(data, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        for row in data:
            writer.writerow(row)

def encrypt():
    cipher_type = cipher_type_var.get()
    algo = algo_var.get()

    with open("plain_text.csv", "r", encoding="utf-8") as file:
        plaintext = file.read()
    
    plaintext_bytes = [ord(c) for c in plaintext]
    data_size = len(plaintext_bytes)

    if cipher_type == "Stream":
        if algo == "RC4":
            key = "mysecretkey"
            key_bytes = [ord(c) for c in key]
            S = rc4_initialize(key_bytes)
            keystream = rc4_generate_keystream(S, data_size)
            ciphertext = xor_with_keystream(plaintext_bytes, keystream)
            
            
            ciphertext_rows = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
            save_to_csv(ciphertext_rows, "cipher_text.csv")
            messagebox.showinfo("Success", "Cipher text is stored in cipher_text.csv file.")
        else:
            messagebox.showinfo("Info", "Code for the selected algorithm is not completed yet.")
    else:
        messagebox.showinfo("Info", "Encryption is only available for stream ciphers.")

def update_algo_options(event):
    cipher_type = cipher_type_var.get()
    if cipher_type == "Stream":
        algo_var.set("RC4")
        algo_menu['values'] = ["RC4", "ChaCha20"]
    elif cipher_type == "Block":
        algo_var.set("AES")
        algo_menu['values'] = ["AES", "DES"]

root = tk.Tk()
root.title("Encryption")

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

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=2, columnspan=2, padx=10, pady=10)

root.mainloop()
