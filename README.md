# Secure Password Manager 🔒

A local, encrypted password vault built with Python. This application features a modern graphical interface and uses industry-standard cryptography to keep your credentials safe from unauthorized access.

## ✨ Features

* **Master Password Protection:** Your vault is secured by a single master password. 
* **Zero Metadata Leakage:** Both your passwords *and* the names of the websites you save are fully encrypted.
* **Modern GUI:** Built with PySide6 for a clean, responsive, dark-mode user experience.
* **Local Storage:** Your data stays on your machine. No cloud syncing, no third-party servers.

## 🛡️ Security Details

This project uses the Python `cryptography` library to ensure robust security:
* **Key Derivation:** Uses **PBKDF2HMAC** (with 480,000 iterations and SHA-256) to stretch your Master Password into a secure key.
* **Encryption:** Uses **Fernet** (AES-128 in CBC mode with a 256-bit HMAC signature) to encrypt the vault payload.
* **Salting:** Each vault generates a unique, random 16-byte salt, ensuring that identical master passwords produce entirely different encryption keys.

## 📦 Installation

**Prerequisites:** You must have [Python 3.7+](https://www.python.org/downloads/) installed on your computer.

1. Clone this repository to your local machine:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/secure-password-manager.git](https://github.com/YOUR_USERNAME/secure-password-manager.git)
   cd secure-password-manager
