import unittest
import os
from aes_crypt import generate_aes_key, aes_encrypt, aes_decrypt
from challenge import generateNonce, calculateChallenge
from rsa_crypt import generate_rsa_keys, rsa_encrypt, rsa_decrypt, key_to_pem, load_public_key_from_pem
from key_management import KeyManagement
import hashlib
import sqlite3

class TestSecureCommunicationSuite(unittest.TestCase):

    def test_aes_encrypt_decrypt(self):
        key = generate_aes_key()
        plaintext = b"Secure communication is essential."
        ciphertext = aes_encrypt(key, plaintext)
        decrypted_text = aes_decrypt(key, ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_generate_nonce(self):
        nonce1 = generateNonce()
        nonce2 = generateNonce()
        self.assertNotEqual(nonce1, nonce2)
        self.assertEqual(len(nonce1), 16)


    def test_calculate_challenge(self):
        nonce = generateNonce()
        key = generate_aes_key()
        challenge = calculateChallenge(nonce, key)
        self.assertEqual(len(challenge), hashlib.sha256().digest_size)

    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = generate_rsa_keys()
        message = b"Secure RSA message"
        ciphertext = rsa_encrypt(public_key, message)
        plaintext = rsa_decrypt(private_key, ciphertext)
        self.assertEqual(message, plaintext)

    def test_rsa_pem_serialization(self):
        private_key, public_key = generate_rsa_keys()
        private_pem = key_to_pem(private_key)
        public_pem = key_to_pem(public_key, is_private=False)
        self.assertTrue(private_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(public_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_key_management(self):
        km = KeyManagement()
        key = b"TestKey1234567890"
        encrypted_key = km.encrypt_key(key)
        decrypted_key = km.decrypt_key(encrypted_key)
        self.assertEqual(key, decrypted_key)

    def test_user_creation(self):
        conn = sqlite3.connect("securityProject.db")
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS test_users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, salt TEXT)")
        username = "test_user"
        password = "securepassword"
        salt = os.urandom(16)
        hashed_password = hashlib.sha256(password.encode() + salt).hexdigest()
        cur.execute("INSERT INTO test_users (username, password, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
        conn.commit()
        cur.execute("SELECT * FROM test_users WHERE username = ?", (username,))
        result = cur.fetchone()
        conn.close()
        self.assertIsNotNone(result)
        self.assertEqual(result[1], username)
        self.assertEqual(result[2], hashed_password)

    def test_key_exchange(self):
        private_key, public_key = generate_rsa_keys()
        aes_key = generate_aes_key()
        encrypted_aes_key = rsa_encrypt(public_key, aes_key)
        decrypted_aes_key = rsa_decrypt(private_key, encrypted_aes_key)
        self.assertEqual(aes_key, decrypted_aes_key)

    def test_aes_stress(self):
        key = generate_aes_key()
        plaintext = os.urandom(1024 * 1024)
        ciphertext = aes_encrypt(key, plaintext)
        decrypted_text = aes_decrypt(key, ciphertext)
        self.assertEqual(plaintext, decrypted_text)

if __name__ == "__main__":
    unittest.main()