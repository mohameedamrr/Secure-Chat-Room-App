import socket
import threading
from formats import MAGENTA,WHITE,Style,BLUE,RED,ITALIC,YELLOW,BRIGHT,GREEN,CYAN,MAGENTA_BG
import hashlib
import re
import aes_crypt
import rsa_crypt
import hashing

# Choosing Nickname
nickname = ""
FORMAT = 'utf-8'
AESKEY = ""

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))

isUserLoggedIn = False

def sendSignupRequst():
    global isUserLoggedIn
    global nickname

    username = '{}'.format(input(f"{MAGENTA}Username: {YELLOW}{ITALIC}"))
    print(Style.RESET_ALL)
    password = '{}'.format(input(f"{MAGENTA}Password: {YELLOW}{ITALIC}"))
    print(Style.RESET_ALL)
    print(f"{BRIGHT}Processing....")
    print(Style.RESET_ALL)

    password = hashing.hash_sha256(password)
    message = f'CREATE <{username}> <{password}>'
    # HMAC = hashing.hash_sha256(message)
    # messageWithHMAC = message + f' <{HMAC}>'
    cipherText = aes_crypt.aes_encrypt(AESKEY, message.encode(FORMAT))
    client.send(cipherText)
    while True:
        try:
            message = client.recv(1024).decode(FORMAT)
            # checkMessageIntegrity(message)
            if message == "ACCEPT 200":
                isUserLoggedIn = True
                nickname = username
                print(f"{BRIGHT}{GREEN}Account Created Successfully!")
                print(Style.RESET_ALL)
                return
            elif message == "USERNAME_TAKEN 400":
                print(f"{BRIGHT}{RED}The username already exists in the database, please try again.")
                print(Style.RESET_ALL)
                return
            elif message == "FAILED 500":
                print(f"{BRIGHT}{RED}An error has occured while creating an account, please try again.")
                print(Style.RESET_ALL)
                return
        except:
            print(f"{BRIGHT}{RED}An error occured with the connection!")
            print(Style.RESET_ALL)
            client.close()
            break

def sendLoginRequest():
    global isUserLoggedIn
    global nickname

    username = '{}'.format(input(f"{MAGENTA}Username: {YELLOW}{ITALIC}"))
    print(Style.RESET_ALL)
    password = '{}'.format(input(f"{MAGENTA}Password: {YELLOW}{ITALIC}"))
    print(Style.RESET_ALL)
    print(f"{BRIGHT}Processing....")
    print(Style.RESET_ALL)

    password = hashlib.sha256(password.encode()).hexdigest()
    message = f'LOGIN <{username}> <{password}>'
    # HMAC = hashing.hash_sha256(message)
    # messageWithHMAC = message + f' <{HMAC}>'
    cipherText = aes_crypt.aes_encrypt(AESKEY, message.encode(FORMAT))
    # print(cipherText)
    client.send(cipherText)
    while True:
        try:
            message = client.recv(1024).decode(FORMAT)
            # checkMessageIntegrity(message)
            if message == "ACCEPT 200":
                isUserLoggedIn = True
                nickname = username
                print(f"{BRIGHT}{GREEN}Login Success!")
                print(Style.RESET_ALL)
                return
            elif message == "NOT_FOUND 401":
                print(f"{BRIGHT}{RED}The username does not exist in the database, please try again.")
                print(Style.RESET_ALL)
                return
            elif message == "INCORRECT_PASSWORD 402":
                print(f"{BRIGHT}{RED}Incorrect Password Entered, please try again.")
                print(Style.RESET_ALL)
                return
            elif message == "FAILED 500":
                print(f"{BRIGHT}{RED}An error has occured while logging you in, please try again.")
                print(Style.RESET_ALL)
                return
        except:
            print(f"{BRIGHT}{RED}An error occured with the connection!")
            print(Style.RESET_ALL)
            client.close()
            break
def connectToServer():
    global AESKEY
    message = 'CONNECT'
    # HMAC = hashing.hash_sha256(message)
    # messageWithHMAC = message + f' <{HMAC}>'
    client.send(message.encode(FORMAT))
    while True:
        try:
            message = client.recv(1024)
            rsaPublicKey = message
            public_key = rsa_crypt.RSA.import_key(rsaPublicKey)
            aesKey = aes_crypt.generate_aes_key()
            rsaEncryptedMessage = rsa_crypt.rsa_encrypt(public_key, aesKey)
            AESKEY = aesKey
            client.send(rsaEncryptedMessage)
            return
        except Exception as e:
            print(e)
            print(f"{BRIGHT}{RED}An error occured with the connection!")
            print(Style.RESET_ALL)
            client.close()
            break

# Listening to Server and Sending Nickname
def receive():
    while True:
        # try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            message = client.recv(1024).decode(FORMAT)
            print(message)
        # except:
        #     # Close Connection When Error
        #     print("An error occured!")
        #     client.close()
        #     break

# Sending Messages To Server
def write():
    while True:
        message = 'MESSAGE {}: {}'.format(nickname, input(''))
        # HMAC = hashing.hash_sha256(message)
        # messageWithHMAC = message + f' <{HMAC}>'
        cipherText = aes_crypt.aes_encrypt(AESKEY, message.encode(FORMAT))
        client.send(cipherText)

def checkMessageIntegrity(message):
    print(22222222222)
    match = re.match(r"(\S+ \d+)<(\w+)>", message)
    print(match.group(1))
    print(match.group(2))

if __name__ == "__main__":
    connectToServer()
    while True:
        if not(isUserLoggedIn):
            # Option to signup or login (When the user chooses signup for the first time there is no need to login)
            print(f"{YELLOW}1- {BLUE}Login\n{YELLOW}2- {BLUE}Signup\n")
            loginOption = '{}'.format(input(f"{MAGENTA}Enter a number: {YELLOW}{ITALIC}"))
            print(Style.RESET_ALL)
            if loginOption == "1":
                sendLoginRequest()
                continue
            elif loginOption == "2":
                sendSignupRequst()
                continue
            else:
                print(f"{RED}Invalid number")
                print(Style.RESET_ALL)
                continue
        receive_thread = threading.Thread(target=receive)
        receive_thread.start()
        write_thread = threading.Thread(target=write)
        write_thread.start()
