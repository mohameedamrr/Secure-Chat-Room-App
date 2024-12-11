import socket
import threading
import re
import sqlite3

# Connection Data
host = '127.0.0.1'
port = 55555

# Starting Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

# Lists For Clients and Their Nicknames
clients = []
nicknames = []

def broadcast(message):
    for client in clients:
        client.send(message.encode('utf-8'))

def loginCommand(messageReceived, address):
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
                broadcast("{} joined!".format(username).encode('utf-8'))
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

# Receiving / Listening Function
def receive(client, address):
    while True:
        # Request And Store Nickname
        messageReceived = client.recv(1024).decode('utf-8').split(" ")
        print(messageReceived)
        match messageReceived[0]:
            case "LOGIN":
                responseCode = loginCommand(messageReceived, address)
                if responseCode == 0:
                    clients.append(client)
                    client.send('ACCEPT 200'.encode('utf-8'))
                    # Print And Broadcast Nickname
                    # client.send('Connected to server!'.encode('utf-8'))
                elif responseCode == 1:
                    client.send('FAILED 500'.encode('utf-8'))
                elif responseCode == 2:
                    client.send('NOT_FOUND 401'.encode('utf-8'))
                elif responseCode == 3:
                    client.send('INCORRECT_PASSWORD 402'.encode('utf-8'))
            case "MESSAGE":
                try:
                    broadcast(messageReceived)
                except:
                    index = clients.index(client)
                    clients.remove(client)
                    client.close()
                    nickname = nicknames[index]
                    broadcast('{} left!'.format(nickname).encode('utf-8'))
                    nicknames.remove(nickname)
                    break

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