class User:
    def __init__(self, username, client, ip_address, port_number, aes_key, public_key_client):
        self.username = username
        self.client = client
        self.ip_address = ip_address
        self.port_number = port_number
        self.aes_key = aes_key
        self.public_key_client = public_key_client