from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rsa_decrypt(public_key, ciphertext):
    cipher = PKCS1_OAEP.new(public_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def key_to_pem(key, is_private=True):
    if is_private:
        return key.export_key(format='PEM')
    else:
        return key.publickey().export_key(format='PEM')

def load_public_key_from_pem(pem_data):
    public_key = RSA.import_key(pem_data)
    return public_key


