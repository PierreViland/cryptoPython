# aesgestion.py

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AesGestion:
    def __init__(self):
        self.aes_key = None
        self.iv = None

    def generate_aes_key(self):
        self.aes_key = get_random_bytes(32)  # 256-bit key

    def save_aes_key_to_file(self, filename):
        if not self.aes_key:
            raise ValueError("AES key not generated.")
        with open(filename, "wb") as f:
            f.write(self.aes_key)

    def load_aes_key_from_file(self, filename):
        with open(filename, "rb") as f:
            self.aes_key = f.read()
        if len(self.aes_key) != 32:
            raise ValueError("Invalid AES-256 key size")

    def encrypt_file(self, input_file, output_file):
        self.iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

        with open(input_file, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open(output_file, "wb") as f:
            f.write(self.iv + ciphertext)

    def decrypt_file(self, input_file, output_file):
        with open(input_file, "rb") as f:
            file_content = f.read()

        self.iv = file_content[:16]
        ciphertext = file_content[16:]

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open(output_file, "wb") as f:
            f.write(plaintext)

    def encrypt_string_to_base64(self, plaintext: str) -> str:
        self.iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded)

        combined = self.iv + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_string_from_base64(self, base64_data: str) -> str:
        combined = base64.b64decode(base64_data)
        self.iv = combined[:16]
        ciphertext = combined[16:]

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
