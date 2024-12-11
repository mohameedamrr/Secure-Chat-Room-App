from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys(key_size=2048):
    """
    Generate an RSA key pair.
    key_size: typical sizes are 2048 or 3072 bits.
    Returns: (private_key, public_key) as RSA key objects
    """
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    """
    Encrypt a message using RSA public key with OAEP padding.
    - public_key: RSA public key object
    - message: bytes to encrypt
    Returns: ciphertext (bytes)
    """
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """
    Decrypt a ciphertext using RSA private key with OAEP padding.
    - private_key: RSA private key object
    - ciphertext: bytes to decrypt
    Returns: plaintext (bytes)
    """
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

if __name__ == "__main__":
    # Example usage:
    priv, pub = generate_rsa_keys(2048)
    msg = b"Hello RSA"
    ct = rsa_encrypt(pub, msg)
    print("Encrypted:", ct)
    dec = rsa_decrypt(priv, ct)
    print("Decrypted:", dec)