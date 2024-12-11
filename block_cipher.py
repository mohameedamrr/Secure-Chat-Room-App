from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class BlockCipher:
    def __init__(self, key=None):
        self.key = key or get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def encrypt(self, plaintext):
        ciphertext, tag = self.cipher.encrypt_and_digest(plaintext.encode())
        return base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode()

    def decrypt(self, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.cipher.nonce)
        plaintext = cipher.decrypt_and_verify(base64.b64decode(ciphertext), base64.b64decode(tag))
        return plaintext.decode()
    
    