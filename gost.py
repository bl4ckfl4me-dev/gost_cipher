import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox

matrix = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
)


def bits_len(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    bits = bits.zfill(8 * ((len(bits) + 7) // 8))
    return len(bits)


def get_out(inright, key):
    out = 0
    temp = (inright + key) % (1 << 32)
    for i in range(8):
        phonetic = (temp >> (4 * i)) & 0b1111
        out |= (matrix[i][phonetic] << (4 * i))
    out = ((out >> 21) | (out << 11)) & 0xFFFFFFFF
    return out


def crypt_operation(inleft, inright, key):
    outleft = inright
    outright = inleft ^ get_out(inright, key)
    return outleft, outright


class Gost:
    def __init__(self):
        self.key = [None] * 8

    def set_key(self, key):
        for i in range(8):
            self.key[i] = (key >> (32 * i)) & 0xFFFFFFFF

    def crypt(self, text):
        text = int(text.encode('utf-8').hex(), 16)
        text_left = text >> 32
        text_right = text & 0xFFFFFFFF
        for q in range(24):
            text_left, text_right = crypt_operation(text_left, text_right, self.key[q % 8])
        for q in range(8):
            text_left, text_right = crypt_operation(text_left, text_right, self.key[7 - q])
        hash = (text_left << 32) | text_right
        return hash


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Шифр Магма")
        self.setGeometry(100, 100, 400, 200)

        layout = QVBoxLayout()

        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Введите 256-битный ключ (32 символа в шестнадцатеричном формате)")
        layout.addWidget(self.key_input)

        self.text_input = QLineEdit(self)
        self.text_input.setPlaceholderText("Введите текст для шифрования")
        layout.addWidget(self.text_input)

        self.encrypt_button = QPushButton("Зашифровать", self)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        layout.addWidget(self.encrypt_button)

        self.result_label = QLabel(self)
        layout.addWidget(self.result_label)

        self.setLayout(layout)

    def encrypt_text(self):
        key_hex = self.key_input.text()
        text = self.text_input.text()

        try:
            key = int(key_hex, 16)
            if len(key_hex) != 64:
                raise ValueError("Ключ должен содержать 64 символов.")
            gost = Gost()
            gost.set_key(key)
            encrypted_hash = gost.crypt(text)
            self.result_label.setText(f"Зашифрованный результат: {hex(encrypted_hash)}")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Произошла ошибка: {str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
