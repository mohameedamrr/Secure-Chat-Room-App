import hashlib

class Hashing:
    @staticmethod
    def hash_sha256(data):
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_md5(data):
        return hashlib.md5(data.encode()).hexdigest()