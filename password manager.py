import json
import sys
import os
import base64
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QFileDialog, QGridLayout, QGroupBox,
        QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
        QPushButton, QTextEdit, QVBoxLayout, QWidget,
    )
except ImportError as exc:
    raise SystemExit("PySide6 is required. Install with: pip install PySide6") from exc


class PasswordManager:
    def __init__(self):
        self.cipher = None
        self.password_file = None
        self.password_dict = {}
        self.current_salt = None

    def _require_vault(self):
        if self.password_file is None or self.cipher is None:
            raise RuntimeError("Create or load a vault file first.")

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derives a secure Fernet key from a master password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000, 
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

    def create_vault(self, path: str, master_password: str):
        if not master_password:
            raise ValueError("A master password is required to create a vault.")
        
        self.password_file = Path(path)
        self.password_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.current_salt = os.urandom(16)
        key = self._derive_key(master_password, self.current_salt)
        self.cipher = Fernet(key)
        
        self.password_dict = {}
        self.save_vault()

    def load_vault(self, path: str, master_password: str):
        if not master_password:
            raise ValueError("A master password is required to open a vault.")
            
        self.password_file = Path(path)
        if not self.password_file.exists():
            raise FileNotFoundError("Vault file not found.")

        raw_data = self.password_file.read_text(encoding="utf-8").strip()
        if not raw_data:
            raise ValueError("Vault file is empty.")

        envelope = json.loads(raw_data)
        if "salt" not in envelope or "payload" not in envelope:
            raise ValueError("Invalid vault format. Missing salt or payload.")

        self.current_salt = base64.b64decode(envelope["salt"])
        key = self._derive_key(master_password, self.current_salt)
        self.cipher = Fernet(key)

        try:
            decrypted_bytes = self.cipher.decrypt(envelope["payload"].encode("utf-8"))
            self.password_dict = json.loads(decrypted_bytes.decode("utf-8"))
        except InvalidToken:
            self.cipher = None
            self.password_dict = {}
            raise InvalidToken("Incorrect Master Password or corrupted vault.")

    def save_vault(self):
        self._require_vault()

        dict_json = json.dumps(self.password_dict)
        encrypted_payload = self.cipher.encrypt(dict_json.encode("utf-8")).decode("utf-8")

        envelope = {
            "salt": base64.b64encode(self.current_salt).decode("utf-8"),
            "payload": encrypted_payload
        }

        self.password_file.write_text(
            json.dumps(envelope, indent=2),
            encoding="utf-8",
        )

    def add_password(self, site, password):
        self._require_vault()
        if not site.strip():
            raise ValueError("Site name cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")
        
        self.password_dict[site.strip()] = password
        self.save_vault()

    def get_password(self, site):
        self._require_vault()
        key = site.strip()
        if key not in self.password_dict:
            raise KeyError(key)
        return self.password_dict[key]

    def delete_password(self, site):
        self._require_vault()
        key = site.strip()
        if key not in self.password_dict:
            raise KeyError(key)
        del self.password_dict[key]
        self.save_vault()

    def list_sites(self):
        self._require_vault()
        return sorted(self.password_dict.keys())


class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.manager = PasswordManager()
        self._build_ui()
        self._apply_style()

    def _build_ui(self):
        self.setWindowTitle("Secure Password Manager")
        self.resize(1100, 760)
        self.setMinimumSize(980, 680)
        self.setFont(QFont("Segoe UI", 10))

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("Encrypted Password Vault")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        files_box = QGroupBox("Vault Setup")
        files_box.setObjectName("card")
        files_grid = QGridLayout(files_box)

        self.vault_path = QLineEdit()
        self.vault_path.setPlaceholderText("Path to vault file (.json)")
        
        self.master_password = QLineEdit()
        self.master_password.setPlaceholderText("Enter Master Password")
        self.master_password.setEchoMode(QLineEdit.Password)

        browse_vault = QPushButton("Browse")
        browse_vault.clicked.connect(self._browse_vault)

        create_vault = QPushButton("Create Vault")
        create_vault.clicked.connect(self._create_vault)
        
        load_vault = QPushButton("Unlock Vault")
        load_vault.clicked.connect(self._load_vault)

        files_grid.addWidget(QLabel("Vault File"), 0, 0)
        files_grid.addWidget(self.vault_path, 0, 1)
        files_grid.addWidget(browse_vault, 0, 2)

        files_grid.addWidget(QLabel("Master Pwd"), 1, 0)
        files_grid.addWidget(self.master_password, 1, 1)
        files_grid.addWidget(create_vault, 1, 2)
        files_grid.addWidget(load_vault, 1, 3)
        files_grid.setColumnStretch(1, 1)

        layout.addWidget(files_box)

        entry_box = QGroupBox("Entry Management")
        entry_box.setObjectName("card")
        entry_grid = QGridLayout(entry_box)

        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Site name (example: github)")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        reveal = QCheckBox("Show password")
        reveal.toggled.connect(
            lambda checked: self.password_input.setEchoMode(
                QLineEdit.Normal if checked else QLineEdit.Password
            )
        )
        reveal_master = QCheckBox("Show master password")
        reveal_master.toggled.connect(
            lambda checked: self.master_password.setEchoMode(
                QLineEdit.Normal if checked else QLineEdit.Password
            )
        )
        files_grid.addWidget(reveal_master, 2, 1)

        add_update = QPushButton("Add / Update")
        add_update.clicked.connect(self._add_or_update)
        get_password = QPushButton("Get Password")
        get_password.clicked.connect(self._get_password)
        delete_password = QPushButton("Delete")
        delete_password.clicked.connect(self._delete_password)
        list_sites = QPushButton("List Sites")
        list_sites.clicked.connect(self._list_sites)

        entry_grid.addWidget(QLabel("Site"), 0, 0)
        entry_grid.addWidget(self.site_input, 0, 1, 1, 3)
        entry_grid.addWidget(QLabel("Password"), 1, 0)
        entry_grid.addWidget(self.password_input, 1, 1, 1, 3)
        entry_grid.addWidget(reveal, 2, 1, 1, 3)

        button_row = QHBoxLayout()
        button_row.addWidget(add_update)
        button_row.addWidget(get_password)
        button_row.addWidget(delete_password)
        button_row.addWidget(list_sites)
        entry_grid.addLayout(button_row, 3, 0, 1, 4)

        layout.addWidget(entry_box)

        activity_box = QGroupBox("Activity Log")
        activity_box.setObjectName("card")
        activity_layout = QVBoxLayout(activity_box)
        self.activity = QTextEdit()
        self.activity.setReadOnly(True)
        activity_layout.addWidget(self.activity)
        layout.addWidget(activity_box, 1)

        self._log("Ready. Select a vault file and enter your master password.")

    def _apply_style(self):
        self.setStyleSheet(
            """
            QWidget { background: #1a2332; color: #e8eef8; }
            QLabel#titleLabel { font-size: 30px; font-weight: 700; color: #64b5f6; }
            QLabel#subtitleLabel { color: #90caf9; }
            QGroupBox#card { border: 1px solid #2d5f8d; border-radius: 12px; margin-top: 12px; padding-top: 10px; background: #1e2d40; }
            QGroupBox#card::title { left: 12px; color: #64b5f6; }
            QLineEdit, QTextEdit { border: 1px solid #2d5f8d; border-radius: 10px; background: #253647; color: #e8eef8; padding: 8px; }
            QPushButton { background: #1f6fdb; color: #ffffff; border: none; border-radius: 10px; padding: 8px 12px; font-weight: 600; }
            QPushButton:hover { background: #2976f6; }
            QPushButton:pressed { background: #1557b8; }
            """
        )

    def _log(self, text):
        self.activity.append(text)

    def _browse_vault(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Vault File", "", "JSON Files (*.json);;All Files (*)")
        if path:
            self.vault_path.setText(path)

    def _create_vault(self):
        path = self.vault_path.text().strip()
        master_pwd = self.master_password.text()
        
        if not path:
            QMessageBox.warning(self, "Missing Vault Path", "Please choose a vault file path.")
            return
        if not master_pwd:
            QMessageBox.warning(self, "Missing Password", "Please enter a Master Password.")
            return
            
        try:
            self.manager.create_vault(path, master_pwd)
            self._log(f"New vault created securely at: {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _load_vault(self):
        path = self.vault_path.text().strip()
        master_pwd = self.master_password.text()
        
        if not path:
            QMessageBox.warning(self, "Missing Vault Path", "Please enter a vault file path.")
            return
        if not master_pwd:
            QMessageBox.warning(self, "Missing Password", "Please enter a Master Password.")
            return
            
        try:
            self.manager.load_vault(path, master_pwd)
            self._log(f"Vault unlocked successfully! ({len(self.manager.password_dict)} entries)")
        except InvalidToken:
            QMessageBox.critical(self, "Access Denied", "Incorrect Master Password or corrupted vault.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _add_or_update(self):
        site = self.site_input.text().strip()
        password = self.password_input.text()
        try:
            self.manager.add_password(site, password)
            self._log(f"Entry saved: {site}")
            self.password_input.clear()
            self.site_input.clear()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _get_password(self):
        site = self.site_input.text().strip()
        if not site:
            QMessageBox.warning(self, "Missing Site", "Please enter a site name.")
            return
        try:
            password = self.manager.get_password(site)
            self.password_input.setText(password)
            self._log(f"Password retrieved for: {site}")
        except KeyError:
            QMessageBox.information(self, "Not Found", f"No password found for '{site}'.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _delete_password(self):
        site = self.site_input.text().strip()
        if not site:
            QMessageBox.warning(self, "Missing Site", "Please enter a site name.")
            return
            
        reply = QMessageBox.question(
            self, "Confirm Delete", f"Delete password for '{site}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
            
        try:
            self.manager.delete_password(site)
            self._log(f"Entry deleted: {site}")
            self.password_input.clear()
            self.site_input.clear()
        except KeyError:
            QMessageBox.information(self, "Not Found", f"No password found for '{site}'.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _list_sites(self):
        try:
            sites = self.manager.list_sites()
            if not sites:
                self._log("No sites found in current vault.")
                return
            self._log("Saved Sites:\n  - " + "\n  - ".join(sites))
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))


_window = None

def main():
    global _window

    app = QApplication.instance()
    is_spyder = True
    
    if app is None:
        app = QApplication(sys.argv)
        is_spyder = False
        
    _window = PasswordManagerGUI()
    _window.show()

    if not is_spyder:
        sys.exit(app.exec())

if __name__ == "__main__":
    main()