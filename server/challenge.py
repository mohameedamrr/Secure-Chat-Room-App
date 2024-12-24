
import secrets
import hashlib

def generateNonce():
    return secrets.token_bytes(16)

def calculateChallenge(nonce, AESKey):
    return hashlib.sha256(nonce + AESKey).digest()