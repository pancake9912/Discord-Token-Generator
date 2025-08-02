import sys
import base64
import random
import string
import json
import csv
import hashlib
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QRadioButton,
    QFileDialog, QProgressBar, QMessageBox, QVBoxLayout, QHBoxLayout,
    QGroupBox
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices

# Token generation functions
def generate_user_id():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=18))

def generate_creation_timestamp():
    return int(datetime.utcnow().timestamp())

def generate_hmac_signature(user_id, creation_timestamp):
    data = f"{user_id}.{creation_timestamp}"
    return hashlib.sha256(data.encode()).hexdigest()

def generate_non_2fa_token():
    user_id = generate_user_id()
    creation_timestamp = generate_creation_timestamp()
    hmac_signature = generate_hmac_signature(user_id, creation_timestamp)
    token = f"{base64.b64encode(user_id.encode()).decode()}.{base64.b64encode(str(creation_timestamp).encode()).decode()}.{hmac_signature}"
    return token

def generate_2fa_token():
    long_base64_string = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
    token = f"mfa.{base64.b64encode(long_base64_string.encode()).decode()}"
    return token

def generate_tokens(num_tokens, token_type):
    if token_type == "non_2fa":
        return [generate_non_2fa_token() for _ in range(num_tokens)]
    else:
        return [generate_2fa_token() for _ in range(num_tokens)]

def save_tokens(tokens, file_format, file_path):
    if file_format == "txt":
        with open(file_path, 'w') as file:
            for token in tokens:
                file.write(token + '\n')
    elif file_format == "csv":
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Token"])
            for token in tokens:
                writer.writerow([token])
    elif file_format == "json":
        with open(file_path, 'w') as file:
            json.dump(tokens, file, indent=4)

class TokenGeneratorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Discord Token Generator")
        self.setFixedSize(600, 480)
        self.setup_ui()

    def setup_ui(self):
        # Fonts and styling
        font_label = "font-size: 14px; font-weight: 600;"
        font_button = """
            QPushButton {
                background-color: #007acc;
                color: white;
                border-radius: 10px;
                padding: 6px 12px;
                font-weight: 700;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #005f9e;
            }
        """
        font_radio = """
            QRadioButton {
                font-size: 14px;
                spacing: 8px;
            }
            QRadioButton::indicator {
                width: 20px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid #007acc;
                background: white;
            }
            QRadioButton::indicator:checked {
                background: #007acc;
            }
        """

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        layout.setSpacing(20)

        # Title label (centered, bigger, bold)
        lbl_title = QLabel("Token Generator")
        lbl_title.setStyleSheet("font-size: 24px; font-weight: 900;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_title)

        # Number of tokens input
        self.input_num = QLineEdit()
        self.input_num.setPlaceholderText("Enter a number of tokens to generate")
        self.input_num.setFixedHeight(30)
        self.input_num.setStyleSheet("font-size: 14px; padding-left: 8px; border-radius: 8px; border: 1px solid #ccc;")
        layout.addWidget(self.input_num)

        # File format group
        file_format_group = QGroupBox("Select File Format:")
        file_format_layout = QHBoxLayout()
        file_format_group.setLayout(file_format_layout)

        self.radio_txt = QRadioButton("Text File (.txt)")
        self.radio_csv = QRadioButton("CSV File (.csv)")
        self.radio_json = QRadioButton("JSON File (.json)")
        self.radio_txt.setChecked(True)

        for r in (self.radio_txt, self.radio_csv, self.radio_json):
            r.setStyleSheet(font_radio)
            file_format_layout.addWidget(r)

        layout.addWidget(file_format_group)

        # Token type group
        token_type_group = QGroupBox("Select Token Type:")
        token_type_layout = QHBoxLayout()
        token_type_group.setLayout(token_type_layout)

        self.radio_non_2fa = QRadioButton("Non-2FA Token")
        self.radio_2fa = QRadioButton("2FA-Enabled Token")
        self.radio_non_2fa.setChecked(True)

        for r in (self.radio_non_2fa, self.radio_2fa):
            r.setStyleSheet(font_radio)
            token_type_layout.addWidget(r)

        layout.addWidget(token_type_group)

        # Buttons horizontal layout
        buttons_layout = QHBoxLayout()

        self.btn_generate = QPushButton("Generate Tokens")
        self.btn_generate.setStyleSheet(font_button)
        self.btn_generate.clicked.connect(self.on_generate_clicked)

        self.btn_copy = QPushButton("Copy Tokens to Clipboard")
        self.btn_copy.setStyleSheet(font_button)
        self.btn_copy.clicked.connect(self.copy_to_clipboard_clicked)

        buttons_layout.addWidget(self.btn_generate)
        buttons_layout.addWidget(self.btn_copy)

        layout.addLayout(buttons_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #007acc;
                border-radius: 10px;
                background-color: #e0e0e0;
            }
            QProgressBar::chunk {
                background-color: #007acc;
                border-radius: 10px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Close button centered
        self.btn_close = QPushButton("Close")
        self.btn_close.setStyleSheet(font_button + "background-color: #cc3300;")
        self.btn_close.clicked.connect(self.close)
        self.btn_close.setFixedWidth(100)
        layout.addWidget(self.btn_close, alignment=Qt.AlignmentFlag.AlignCenter)

        # Bottom horizontal layout for "Made by" label and GitHub button
        bottom_layout = QHBoxLayout()

        made_by_label = QLabel("Made by pancake_9912 on Github")
        made_by_label.setStyleSheet("color: #ffffff; font-size: 12px;")
        bottom_layout.addWidget(made_by_label, alignment=Qt.AlignmentFlag.AlignLeft)

        self.btn_github = QPushButton("GitHub")
        self.btn_github.setStyleSheet("""
            QPushButton {
                background-color: #24292e;
                color: white;
                border-radius: 10px;
                padding: 6px 12px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #444c56;
            }
        """)
        self.btn_github.setFixedWidth(80)
        self.btn_github.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/pancake9912")))
        bottom_layout.addWidget(self.btn_github, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addLayout(bottom_layout)

        self.setLayout(layout)

    def get_file_format(self):
        if self.radio_txt.isChecked():
            return "txt"
        elif self.radio_csv.isChecked():
            return "csv"
        elif self.radio_json.isChecked():
            return "json"

    def get_token_type(self):
        if self.radio_non_2fa.isChecked():
            return "non_2fa"
        else:
            return "2fa"

    def on_generate_clicked(self):
        try:
            num_tokens = int(self.input_num.text())
            if num_tokens <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a positive integer for number of tokens.")
            return

        file_format = self.get_file_format()
        token_type = self.get_token_type()

        options = QFileDialog.Option.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Tokens", "",
                                                   f"{file_format.upper()} Files (*.{file_format});;All Files (*)",
                                                   options=options)
        if not file_path:
            return

        tokens = generate_tokens(num_tokens, token_type)
        try:
            save_tokens(tokens, file_format, file_path)
            QMessageBox.information(self, "Success", f"Generated {num_tokens} tokens saved to:\n{file_path}")
            self.progress_bar.setValue(100)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save tokens:\n{str(e)}")
            self.progress_bar.setValue(0)

    def copy_to_clipboard_clicked(self):
        try:
            num_tokens = int(self.input_num.text())
            if num_tokens <= 0:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a positive integer for number of tokens.")
            return

        token_type = self.get_token_type()
        tokens = generate_tokens(num_tokens, token_type)
        clipboard_content = "\n".join(tokens)
        QApplication.clipboard().setText(clipboard_content)
        QMessageBox.information(self, "Copied", "Tokens copied to clipboard!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TokenGeneratorApp()
    window.show()
    sys.exit(app.exec())
