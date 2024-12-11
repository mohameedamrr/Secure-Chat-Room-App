import socket
import threading
import re
import sqlite3
import rsa_crypt


# Connection Data
host = '127.0.0.1'
port = 55555
FORMAT = 'utf-8'

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
(private_key, public_key) = rsa_crypt.generate_rsa_keys()
# Lists For Clients and Their Nicknames
clients = []
nicknames = []

def broadcast(message, messageOwner):
    for client in clients:
        if client == messageOwner:
            continue
        client.send(message.encode(FORMAT))

def loginCommand(messageReceived, address, client):
    #  ACCEPT 200 -> 0 /// FAILED 500 -> 1/// NOT_FOUND 401 -> 2 /// INCORRECT_PASSWORD 402 -> 3
    try:
        ip, port = address
        username = re.search(r'<(.*?)>', messageReceived[1]).group(1)
        password = re.search(r'<(.*?)>', messageReceived[2]).group(1)
        if username == "" or password == "":
            return 1
        conn = sqlite3.connect("securityProject.db")
        cur = conn.cursor()

        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cur.fetchone()

        if result:
            stored_password = result[0]
            if stored_password == password:
                nicknames.append(username)
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
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            nicknames.append(username)
            return 0
    except:
        return 2

def connectCommand(messageReceived, address, client):
    # ACCEPT 200 -> 0 /// USERNAME_TAKEN 400 -> 1 /// FAILED 500 -> 2
    try:
        publicKey = 'PUBLIC ' + str(public_key)
        print(publicKey)
        client.send(publicKey.encode(FORMAT))
        while True:
            message = client.recv(1024).decode(FORMAT)
            decryptedRSAMessage = rsa_crypt.decrypt(message)
            print(message)
    except:
        return 2

# Receiving / Listening Function
def receive(client, address):
    while True:
        # Request And Store Nickname
        message = client.recv(1024).decode(FORMAT)
        messageReceived = message.split(" ")
        match messageReceived[0]:
            case "CONNECT":
                responseCode = connectCommand(messageReceived, address, client)
            case "LOGIN":
                responseCode = loginCommand(messageReceived, address, client)
                if responseCode == 0:
                    clients.append(client)
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
                except:
                    index = clients.index(client)
                    clients.remove(client)
                    client.close()
                    nickname = nicknames[index]
                    broadcast('{} left!'.format(nickname), client)
                    nicknames.remove(nickname)
                    break
            case "CREATE":
                responseCode = signupCommand(messageReceived, address)
                if responseCode == 0:
                    clients.append(client)
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
            print(f"Connected with {ip}:{port}")
            thread = threading.Thread(target=receive, args=(client,address,))
            thread.start()
        except:
            pass

startConnectionWithClients()