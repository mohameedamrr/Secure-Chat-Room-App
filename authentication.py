from hashing import Hashing

class Authentication:
    def __init__(self):
        self.credentials = {}

    def register_user(self, username, password):
        self.credentials[username] = Hashing.hash_sha256(password)

    def authenticate_user(self, username, password):
        hashed_password = Hashing.hash_sha256(password)
        return self.credentials.get(username) == hashed_password