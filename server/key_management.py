from cryptography.fernet import Fernet

class KeyManagement:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt_key(self, key):
        return self.cipher.encrypt(key)

    def decrypt_key(self, encrypted_key):
        return self.cipher.decrypt(encrypted_key)