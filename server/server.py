import socket
import threading
import re
import sqlite3
import rsa_crypt
import aes_crypt
from user import User
import hashing
import challenge
from dotenv import load_dotenv, dotenv_values
import os
import base64
import ast
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

host = '127.0.0.1'
port = 55555
FORMAT = 'utf-8'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
PRIVATEKEY = ""
users = []

def getPrivateKey():
    global PRIVATEKEY
    conn = sqlite3.connect("server/securityProject.db")
    cur = conn.cursor()
    cur.execute("SELECT private_key FROM keys WHERE id = 1")
    result = cur.fetchone()
    load_dotenv()
    masterKey = base64.b64decode(os.getenv("MASTERKEY"))
    if result:
        encryptedPrivateKey = result[0]
        private_pem = aes_crypt.aes_decrypt(masterKey, encryptedPrivateKey).decode(FORMAT)
        PRIVATEKEY = rsa_crypt.RSA.import_key(private_pem)
    else:
        (private_key, public_key) = rsa_crypt.generate_rsa_keys()
        private_pem = rsa_crypt.key_to_pem(private_key, is_private=True).decode('utf-8')
        public_pem = rsa_crypt.key_to_pem(public_key, is_private=False).decode('utf-8')
        encrypted_private_pem = aes_crypt.aes_encrypt(masterKey, private_pem.encode(FORMAT))
        cur.execute("INSERT INTO keys (id, private_key, public_key) VALUES (?, ?, ?)", (1, encrypted_private_pem, public_pem))
        conn.commit()
        PRIVATEKEY = private_key




def broadcast(message, messageOwner):
    for user in users:
        try:
            if user.client == messageOwner or user.client == "":
                continue
            delimiter = b":::DELIMITER:::"
            hashMessage = SHA256.new(message.encode(FORMAT))
            encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
            encryptedMessage = aes_crypt.aes_encrypt(user.aes_key, message.encode(FORMAT))
            newMesssage = encryptedMessage + delimiter + encryptedHash
            user.client.send(newMesssage)
        except Exception as e:
            print(e)
            pass


def loginCommand(message, address, client):
    #  ACCEPT 200 -> 0 /// FAILED 500 -> 1/// NOT_FOUND 401 -> 2 /// INCORRECT_PASSWORD 402 -> 3
    try:
        integrityCheck = checkMessageIntegrity(message)
        if integrityCheck != 1:
            return 1
        ip, port = address
        messageList = message.split(" ")
        username = re.search(r'<(.*?)>', messageList[1]).group(1)
        password = re.search(r'<(.*?)>', messageList[2]).group(1)
        if username == "" or password == "":
            return 1
        conn = sqlite3.connect("server/securityProject.db")
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

def signupCommand(message, address):
    # ACCEPT 200 -> 0 /// USERNAME_TAKEN 400 -> 1 /// FAILED 500 -> 2
    try:
        integrityCheck = checkMessageIntegrity(message)
        if integrityCheck != 1:
            return 1
        messageList = message.split(" ")
        ip, port = address
        username = re.search(r'<(.*?)>', messageList[1]).group(1)
        password = re.search(r'<(.*?)>', messageList[2]).group(1)

        conn = sqlite3.connect("server/securityProject.db")
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

def connectCommand(message, address, client):
    # ACCEPT 200 -> 0 /// FAILED 500 -> 1
    #try:
        delimiter = b":::DELIMITER:::"
        parts = message.split(delimiter, maxsplit=1)
        decryptedMessage = rsa_crypt.rsa_decrypt(PRIVATEKEY, parts[0][:-2]).decode(FORMAT).split(" ")
        messageCommand = decryptedMessage[0]
        userAESKey = ast.literal_eval(decryptedMessage[1])
        receivedNonce = ast.literal_eval(decryptedMessage[2])
        publicKeyClientPem = parts[1][2:].decode("utf-8").strip("'").replace("\\n", "\n")
        newNonce = challenge.calculateChallenge(receivedNonce, userAESKey)
        if messageCommand != "CONNECT":
            return 1
        # TODO: make digital signature
        # newMesssage = "ACCEPT_200" + f'{":::DELIMITER:::"}{newNonce}' + f'{":::DELIMITER:::"}{1}'
        initialMessage = "ACCEPT_200" + f'{":::DELIMITER:::"}{newNonce}'
        hashMessage = SHA256.new(initialMessage.encode(FORMAT))
        print(hashMessage.hexdigest())
        signature = pkcs1_15.new(PRIVATEKEY).sign(hashMessage)
        publicKeyClient = rsa_crypt.load_public_key_from_pem(publicKeyClientPem.encode(FORMAT))
        encryptedMessage = rsa_crypt.rsa_encrypt(publicKeyClient, initialMessage.encode(FORMAT))
        newMesssage = encryptedMessage + delimiter + encryptedHash
        client.send(newMesssage)
        ip, port = address
        user_index = -1
        for i in range(0, len(users)):
            if users[i].ip_address == ip and users[i].port_number == port:
                user_index = i
                break
        users[user_index].aes_key = userAESKey
        users[user_index].public_key_client = publicKeyClient
        return 0
    # except Exception as e:
    #     print(e)
    #     return 1

def checkMessageIntegrity(message , hashvalue):
    try:
        messageList = message.split(" ")
        sentHashValue = re.search(r'<(.*?)>', messageList[-1]).group(1)
        messageWithoutHash = message.replace(f'<{sentHashValue}>', "")[:-1]
        hashValue = hashing.hash_sha256(messageWithoutHash)
        if hashValue == sentHashValue:
            return 1
        else:
            return 0
    except Exception as e:
        print(e)
        return 2

def receive(client, address):
    isFirstMessage = True
    ip, port = address
    user_index = -1
    for i in range(0, len(users)):
        if users[i].ip_address == ip and users[i].port_number == port:
            user_index = i
    while True:
        if isFirstMessage == True:
            message = client.recv(1024)
            responseCode = connectCommand(message, address, client)
            isFirstMessage = False
        else:
            message = client.recv(1024)
            aesKey = users[user_index].aes_key
            message = aes_crypt.aes_decrypt(aesKey, message).decode(FORMAT)
            messageReceived = message.split(" ")
            ip, port = address
            match messageReceived[0]:
                case "LOGIN":
                    responseCode = loginCommand(message, address, client)
                    if responseCode == 0:
                        users[user_index].client = client
                        message = 'ACCEPT 200'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)
                    elif responseCode == 1:
                        message = 'FAILED 500'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)
                    elif responseCode == 2:
                        message = 'NOT_FOUND 401'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)
                    elif responseCode == 3:
                        message = 'INCORRECT_PASSWORD 402'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)
                case "MESSAGE":
                    try:
                        integrityCheck = checkMessageIntegrity(message)
                        if integrityCheck != 1:
                            return 1
                        messageList = message[8:].split(" ")
                        sentHashValue = re.search(r'<(.*?)>', messageList[-1]).group(1)
                        messageWithoutHash = message[8:].replace(f'<{sentHashValue}>', "")[:-1]
                        broadcast(messageWithoutHash, client)
                    except Exception as e:
                        print(e)
                        users[user_index].client.close()
                        broadcast('{} left!'.format(users[user_index].username), users[user_index].client)
                        users.remove(users[user_index])
                        break
                case "CREATE":
                    responseCode = signupCommand(message, address)
                    if responseCode == 0:
                        users[user_index].client = client
                        message = 'ACCEPT 200'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)
                    elif responseCode == 1:
                        message = 'USERNAME_TAKEN 400'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)
                    elif responseCode == 2:
                        message = 'FAILED 500'
                        delimiter = b":::DELIMITER:::"
                        hashMessage = SHA256.new(message.encode(FORMAT))
                        encryptedHash = rsa_crypt.rsa_encrypt(PRIVATEKEY, hashMessage)
                        encryptedMessage = aes_crypt.aes_encrypt(users[user_index].aes_key, message.encode(FORMAT))
                        newMesssage = encryptedMessage + delimiter + encryptedHash
                        client.send(newMesssage)

def startConnectionWithClients():
    while True:
        try:
            client, address = server.accept()
            ip, port = address
            users.append(User("", "", ip, port, "", ""))
            print(f"Connected with {ip}:{port}")
            thread = threading.Thread(target=receive, args=(client,address,))
            thread.start()
        except Exception as e:
            print(e)
            pass

getPrivateKey()
startConnectionWithClients()
