

# Cipher Key Stream Generator

## Overview

This project is a **Cipher Key Stream Generator** built using **Python** and **Tkinter**. It allows users to generate key streams for encryption using **stream cipher algorithms** such as **RC4** and **ChaCha20**. The key streams are generated based on user-selected algorithms and can be saved to CSV files for further use.

## Features

- **Stream Cipher Support**: 
  - RC4
  - ChaCha20
- Generates a **key stream** of 100,000 rows by 8 bytes.
- Key streams are saved in a CSV format.
- Simple and intuitive **Graphical User Interface (GUI)** using Tkinter.

## Algorithms Implemented

1. **RC4**: 
   - Implements the **Key Scheduling Algorithm (KSA)** and **Pseudo-Random Generation Algorithm (PRGA)** to generate key streams.
   
2. **ChaCha20**: 
   - Uses Python's `cryptography` library to generate a ChaCha20-based key stream with secure random key and nonce generation.

## Files

- `RC4_A5.csv` - Stores the RC4-generated key stream.
- `ChaCha_A5.csv` - Stores the ChaCha20-generated key stream.

## Getting Started

### Prerequisites

You need to have **Python 3.x** installed along with the following libraries:

- **tkinter** (comes with Python)
- **cryptography**
- **secrets**

Install `cryptography` with pip:

```bash
pip install cryptography
```


   

## How to Use

1. Select a **Cipher Type** (Stream or Block).
2. Choose a **Stream Cipher Algorithm** (RC4 or ChaCha20).
3. Click **Generate Key Stream**.
4. The generated key stream will be saved in a CSV file (`RC4_A5.csv` or `ChaCha_A5.csv`).



## Future Enhancements

- Implement **Block Cipher Algorithms** (AES, DES).
- Add **custom key input** for more flexibility.
- Display key stream directly in the GUI.

