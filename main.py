from block_cipher import BlockCipher
from public_key import PublicKeyCrypto
from hashing import Hashing
from key_management import KeyManagement
from authentication import Authentication
# from internet_security import InternetSecurity

if __name__ == "__main__":
    # Example usage of all modules
    print("### Block Cipher Example ###")
    aes = BlockCipher()
    ciphertext, tag = aes.encrypt("Hello, secure world!")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {aes.decrypt(ciphertext, tag)}\n")

    print("### Public Key Cryptosystem Example ###")
    rsa_crypto = PublicKeyCrypto()
    rsa_encrypted = rsa_crypto.encrypt("Secure this message!")
    print(f"Encrypted (RSA): {rsa_encrypted}")
    print(f"Decrypted (RSA): {rsa_crypto.decrypt(rsa_encrypted)}\n")

    print("### Hashing Example ###")
    hashed_sha256 = Hashing.hash_sha256("data integrity check")
    hashed_md5 = Hashing.hash_md5("data integrity check")
    print(f"SHA-256 Hash: {hashed_sha256}")
    print(f"MD5 Hash: {hashed_md5}\n")

    print("### Key Management Example ###")
    key_manager = KeyManagement()
    encrypted_key = key_manager.encrypt_key(b"MySuperSecretKey")
    print(f"Encrypted Key: {encrypted_key}")
    print(f"Decrypted Key: {key_manager.decrypt_key(encrypted_key)}\n")

    print("### Authentication Example ###")
    auth = Authentication()
    auth.register_user("user1", "password123")
    print(f"Authentication successful: {auth.authenticate_user('user1', 'password123')}")
    print(f"Authentication failed: {auth.authenticate_user('user1', 'wrongpassword')}\n")

    print("### Internet Security Example ###")
    # InternetSecurity.secure_request("https://example.com")