from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class PublicKeyCrypto:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.cipher = PKCS1_OAEP.new(self.public_key)

    def encrypt(self, plaintext):
        ciphertext = self.cipher.encrypt(plaintext.encode())
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext):
        decipher = PKCS1_OAEP.new(self.key)
        plaintext = decipher.decrypt(base64.b64decode(ciphertext))
        return plaintext.decode()