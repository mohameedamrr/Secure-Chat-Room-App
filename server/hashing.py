import hashlib

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()