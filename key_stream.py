import tkinter as tk
from tkinter import ttk, messagebox
import csv
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

def rc4_initialize(key):
    S = list(range(256))  # Initialize state array with values 0 to 255
    j = 0

    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    return S

def rc4_generate_keystream(S, length):
    i = j = 0
    key_stream = []

    # Pseudo-Random Generation Algorithm (PRGA)
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key_stream.append(S[(S[i] + S[j]) % 256])

    return key_stream

def generate_keystream_chacha20(key, nonce, length):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b'\x00' * length)

def save_key_stream_to_csv(key_stream, rows, cols):
    with open("RC4_A5.csv" if algo_var.get() == "RC4" else "ChaCha_A5.csv", mode='w', newline='') as file:
        writer = csv.writer(file)
        for i in range(rows):
            writer.writerow(key_stream[i*cols:(i+1)*cols])

def generate_key_stream():
    cipher_type = cipher_type_var.get()
    algo = algo_var.get()

    rows = 100000 
    cols = 8  
    data_size = rows * cols  

    if cipher_type == "Stream":
        if algo == "RC4":
            key = "mysecretkey"
            key_bytes = [ord(c) for c in key]
            S = rc4_initialize(key_bytes)
            key_stream = rc4_generate_keystream(S, data_size)
            save_key_stream_to_csv(key_stream, rows, cols)
            messagebox.showinfo("Success", "Key stream is stored in RC4_A5.csv file.")
        elif algo == "ChaCha20":
            key = secrets.token_bytes(32)  # ChaCha20 key size is 32 bytes
            nonce = secrets.token_bytes(16)  # ChaCha20 nonce size is 16 bytes
            key_stream = generate_keystream_chacha20(key, nonce, data_size)
            save_key_stream_to_csv(key_stream, rows, cols)
            messagebox.showinfo("Success", "Key stream is stored in ChaCha_A5.csv file.")
        else:
            messagebox.showinfo("Info", "Code for the selected algorithm is not completed yet.")
    elif cipher_type == "Block":
        messagebox.showinfo("Info", "Code for the selected algorithm is not completed yet.")
    else:
        messagebox.showerror("Selection Error", "Please select a valid cipher type and algorithm.")

def update_algo_options(event):
    cipher_type = cipher_type_var.get()
    if cipher_type == "Stream":
        algo_var.set("RC4")
        algo_menu['values'] = ["RC4", "ChaCha20"]
    elif cipher_type == "Block":
        algo_var.set("AES")
        algo_menu['values'] = ["AES", "DES"]


root = tk.Tk()
root.title("Cipher Key Stream Generator")


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


generate_button = tk.Button(root, text="Generate Key Stream", command=generate_key_stream)
generate_button.grid(row=2, columnspan=2, padx=10, pady=20)


root.mainloop()
