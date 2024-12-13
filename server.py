import socket
import threading
import re
import sqlite3
import rsa_crypt
import aes_crypt
from user import User

# Connection Data
host = '127.0.0.1'
port = 55555
FORMAT = 'utf-8'

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
(private_key, public_key) = rsa_crypt.generate_rsa_keys()
SERVERAESKEY = aes_crypt.generate_aes_key()
users = []

def broadcast(message, messageOwner):
        for user in users:
            try:
                if user.client == messageOwner or user.client == "":
                    continue
                user.client.send(message.encode(FORMAT))
            except Exception as e:
                print(e)
                pass


def loginCommand(messageReceived, address, client):
    #  ACCEPT 200 -> 0 /// FAILED 500 -> 1/// NOT_FOUND 401 -> 2 /// INCORRECT_PASSWORD 402 -> 3
    try:
        ip, port = address
        username = re.search(r'<(.*?)>', messageReceived[1]).group(1)
        password = re.search(r'<(.*?)>', messageReceived[2]).group(1)
        # hash = re.search(r'<(.*?)>', messageReceived[3]).group(1)
        # print(hash)
        if username == "" or password == "":
            return 1
        conn = sqlite3.connect("securityProject.db")
        cur = conn.cursor()

        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cur.fetchone()

        if result:
            stored_password = result[0]
            if stored_password == password:
                for user in users:
                    if user.ip_address == ip and user.port_number == port:
                        user.username = username
                print("Nickname is {}".format(username))
                broadcast("{} joined!".format(username), client)
                return 0
            else:
                # Passwords do not match
                return 3
        else:
            # Username not found
            return 2
    except Exception as e:
        print(e)
        return 1

def signupCommand(messageReceived, address):
    # ACCEPT 200 -> 0 /// USERNAME_TAKEN 400 -> 1 /// FAILED 500 -> 2
    try:
        ip, port = address
        username = re.search(r'<(.*?)>', messageReceived[1]).group(1)
        password = re.search(r'<(.*?)>', messageReceived[2]).group(1)

        conn = sqlite3.connect("securityProject.db")
        cur = conn.cursor()

        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cur.fetchone()

        if result:
            # Username already exists
            return 1
        else:
            cur.execute("INSERT INTO users (username, password, AESKEY) VALUES (?, ?, ?)", (username, password, ""))
            conn.commit()
            for user in users:
                    if user.ip_address == ip and user.port_number == port:
                        user.username = username
            return 0
    except Exception as e:
        print(e)
        return 2

def connectCommand(messageReceived, address, client):
    # ACCEPT 200 -> 0 /// FAILED 500 -> 1
    try:
        public_key_pem = public_key.export_key(format="PEM")
        publicKeyMessage = public_key_pem
        ip, port = address
        client.send(publicKeyMessage)
        user_index = -1
        while True:
            for i in range(0, len(users)):
                if users[i].ip_address == ip and users[i].port_number == port:
                    user_index = i
            rsaCipherText = client.recv(2048)
            userAESKey = rsa_crypt.rsa_decrypt(private_key, rsaCipherText)
            print(userAESKey)

            users[user_index].aes_key = userAESKey
            return 0
    except Exception as e:
        print(e)
        return 1

def saveKey(address):
    # KEY STORAGE
    ip, port = address
    user_index = -1
    for i in range(0, len(users)):
        if users[i].ip_address == ip and users[i].port_number == port:
            user_index = i
    if user_index != -1:
        print(users[user_index].aes_key)
        encryptedAESKey = aes_crypt.aes_encrypt(SERVERAESKEY, users[user_index].aes_key)
        print(encryptedAESKey)
        conn = sqlite3.connect("securityProject.db")
        cur = conn.cursor()
        cur.execute("UPDATE users SET AESKEY = ? WHERE USERNAME = ?", (encryptedAESKey, users[user_index].username))
        conn.commit()

# Receiving / Listening Function
def receive(client, address):
    isFirstMessage = True
    while True:
        # Request And Store Nickname
        ip, port = address
        if isFirstMessage == False:
            message = client.recv(4096)
            print(message)
            aesKey = ""
            for user in users:
                if user.ip_address == ip and user.port_number == port:
                    aesKey = user.aes_key
            print(aesKey)
            message = aes_crypt.aes_decrypt(aesKey, message).decode(FORMAT)
            print(message)
        else:
            message = client.recv(2048).decode(FORMAT)
            isFirstMessage = False
        messageReceived = message.split(" ")
        ip, port = address
        match messageReceived[0]:
            case "CONNECT":
                responseCode = connectCommand(messageReceived, address, client)
            case "LOGIN":
                responseCode = loginCommand(messageReceived, address, client)
                if responseCode == 0:
                    saveKey(address)
                    for user in users:
                        if user.ip_address == ip and user.port_number == port:
                            user.client = client
                    client.send('ACCEPT 200'.encode(FORMAT))
                elif responseCode == 1:
                    client.send('FAILED 500'.encode(FORMAT))
                elif responseCode == 2:
                    client.send('NOT_FOUND 401'.encode(FORMAT))
                elif responseCode == 3:
                    client.send('INCORRECT_PASSWORD 402'.encode(FORMAT))
            case "MESSAGE":
                try:
                    broadcast(message[8:], client)
                except Exception as e:
                    print(e)
                    index = -1
                    for i in range(0, len(users)):
                        if users[i].ip_address == ip and users[i].port_number == port:
                            index = i
                    users[index].client.close()
                    broadcast('{} left!'.format(users[index].username), users[index].client)
                    users.remove(users[index])
                    break
            case "CREATE":
                responseCode = signupCommand(messageReceived, address)
                if responseCode == 0:
                    saveKey(address)
                    for user in users:
                        if user.ip_address == ip and user.port_number == port:
                            user.client = client
                    client.send('ACCEPT 200'.encode(FORMAT))
                elif responseCode == 1:
                    client.send('USERNAME_TAKEN 400'.encode(FORMAT))
                elif responseCode == 2:
                    client.send('FAILED 500'.encode(FORMAT))

def startConnectionWithClients():
    while True:
        try:
            client, address = server.accept()
            ip, port = address
            users.append(User("", "", ip, port, ""))
            print(f"Connected with {ip}:{port}")
            thread = threading.Thread(target=receive, args=(client,address,))
            thread.start()
        except Exception as e:
            print(e)
            pass

startConnectionWithClients()