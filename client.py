import socket
import threading
from formats import MAGENTA,WHITE,Style,BLUE,RED,ITALIC,YELLOW,BRIGHT,GREEN,CYAN,MAGENTA_BG
import hashlib
import re
import aes_crypt
import rsa_crypt

# Choosing Nickname
nickname = ""
FORMAT = 'utf-8'

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('3.125.188.168', 17126))

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

    password = hashlib.sha256(password.encode()).hexdigest()
    message = f'CREATE <{username}> <{password}>'
    client.send(message.encode(FORMAT))
    while True:
        try:
            message = client.recv(1024).decode(FORMAT)
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
    client.send(message.encode(FORMAT))
    while True:
        try:
            message = client.recv(1024).decode(FORMAT)
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
    message = 'CONNECT'
    client.send(message.encode(FORMAT))
    while True:
        # try:
            message = client.recv(1024).decode(FORMAT)
            print(message)
            messageReceived = message.split(" ")
            if messageReceived[0] == "PUBLIC":
                rsaPublicKey = messageReceived[1].encode(FORMAT)
                aesKey = aes_crypt.generate_aes_key()
                aesMessage = "AES " + str(aesKey)
                rsaEncryptedMessage = rsa_crypt.rsa_encrypt(rsaPublicKey, aesMessage.encode(FORMAT))
                print(aesMessage)
                client.send(rsaEncryptedMessage.encode(FORMAT))
                return
        # except Exception as e:
        #     print(e)
        #     print(f"{BRIGHT}{RED}An error occured with the connection!")
        #     print(Style.RESET_ALL)
        #     client.close()
        #     break

# Listening to Server and Sending Nickname
def receive():
    while True:
        # try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            message = client.recv(1024).decode(FORMAT)
            if message == 'NICK':
                client.send(nickname.encode(FORMAT))
            else:
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
        client.send(message.encode(FORMAT))


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
