class User:
    def __init__(self, username, client, ip_address, port_number, aes_key):
        self.username = username
        self.client = client
        self.ip_address = ip_address
        self.port_number = port_number
        self.aes_key = aes_key