from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_aes_key(key_size=256):
    """
    Generate a random AES key.
    key_size: 128, 192, or 256 bits.
    Returns: bytes (the AES key)
    """
    if key_size not in [128, 192, 256]:
        raise ValueError("key_size must be 128, 192, or 256 bits.")
    return get_random_bytes(key_size // 8)

def aes_encrypt(key, plaintext):
    """
    Encrypt plaintext using AES in CBC mode.
    - key: The AES key (bytes)
    - plaintext: The data to encrypt (bytes)
    Returns: (iv, ciphertext) both as bytes
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    """
    Decrypt ciphertext using AES in CBC mode.
    - key: The AES key (bytes)
    - iv: The initialization vector (16 bytes)
    - ciphertext: The data to decrypt (bytes)
    Returns: plaintext (bytes)
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
