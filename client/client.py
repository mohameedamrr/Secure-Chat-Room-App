import os
import socket
import threading
from formats import MAGENTA,WHITE,Style,BLUE,RED,ITALIC,YELLOW,BRIGHT,GREEN,CYAN,MAGENTA_BG
import re
import aes_crypt
import rsa_crypt
import hashing
import challenge
from dotenv import load_dotenv, dotenv_values

nickname = ""
FORMAT = 'utf-8'
AESKEY = ""

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
    HMAC = hashing.hash_sha256(message)
    messageWithHMAC = message + f' <{HMAC}>'
    cipherText = aes_crypt.aes_encrypt(AESKEY, messageWithHMAC.encode(FORMAT))
    client.send(cipherText)
    while True:
        try:
            message = client.recv(1024)
            message = aes_crypt.aes_decrypt(AESKEY, message).decode(FORMAT)
            integrityCheck = checkMessageIntegrity(message)
            if integrityCheck != 1:
                return
            if "ACCEPT 200" in message:
                isUserLoggedIn = True
                nickname = username
                print(f"{BRIGHT}{GREEN}Account Created Successfully!")
                print(Style.RESET_ALL)
                return
            elif "USERNAME_TAKEN 400" in message:
                print(f"{BRIGHT}{RED}The username already exists in the database, please try again.")
                print(Style.RESET_ALL)
                return
            elif "FAILED 500" in message:
                print(f"{BRIGHT}{RED}An error has occured while creating an account, please try again.")
                print(Style.RESET_ALL)
                return
        except Exception as e:
            print(e)
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

    password = hashing.hash_sha256(password)
    message = f'LOGIN <{username}> <{password}>'
    HMAC = hashing.hash_sha256(message)
    messageWithHMAC = message + f' <{HMAC}>'
    cipherText = aes_crypt.aes_encrypt(AESKEY, messageWithHMAC.encode(FORMAT))
    client.send(cipherText)
    while True:
        try:
            message = client.recv(1024)
            message = aes_crypt.aes_decrypt(AESKEY, message).decode(FORMAT)
            integrityCheck = checkMessageIntegrity(message)
            if integrityCheck != 1:
                return
            if "ACCEPT 200" in message:
                isUserLoggedIn = True
                nickname = username
                print(f"{BRIGHT}{GREEN}Login Success!")
                print(Style.RESET_ALL)
                return
            elif "NOT_FOUND 401" in message:
                print(f"{BRIGHT}{RED}The username does not exist in the database, please try again.")
                print(Style.RESET_ALL)
                return
            elif "INCORRECT_PASSWORD 402" in message:
                print(f"{BRIGHT}{RED}Incorrect Password Entered, please try again.")
                print(Style.RESET_ALL)
                return
            elif "FAILED 500" in message:
                print(f"{BRIGHT}{RED}An error has occured while logging you in, please try again.")
                print(Style.RESET_ALL)
                return
        except Exception as e:
            print(e)
            print(f"{BRIGHT}{RED}An error occured with the connection!")
            print(Style.RESET_ALL)
            client.close()
            break

def connectToServer():
    global AESKEY
    message = 'CONNECT'
    nonce = challenge.generateNonce()
    AESKEY = aes_crypt.generate_aes_key()
    (private_key_client, public_key_client) = rsa_crypt.generate_rsa_keys()
    hmacKey = '1'
    pem_public_key_client = rsa_crypt.key_to_pem(public_key_client, is_private=False)
    print(pem_public_key_client)
    messageToEncrypt = message + f' {AESKEY}' + f' {nonce}'
    load_dotenv()
    PUBLICKEY = rsa_crypt.RSA.import_key(os.getenv("SERVER_PUBLIC_KEY"))
    encryptedMessage = rsa_crypt.rsa_encrypt(PUBLICKEY, messageToEncrypt.encode(FORMAT))
    delimiter = b":::DELIMITER:::"
    totalMessage = encryptedMessage + (f'{delimiter}{pem_public_key_client}').encode(FORMAT)
    client.send(totalMessage)
    while True:
        try:
            message = client.recv(1024)
            decryptedMessage = rsa_crypt.rsa_decrypt(private_key_client, message).decode(FORMAT)
            messageList = decryptedMessage.split(" ")
            messageStatus = re.search(r'<(.*?)>', messageList[0]).group(1)
            receivedNonce = re.search(r'<(.*?)>', messageList[1]).group(1)
            digitalSignature = re.search(r'<(.*?)>', messageList[2]).group(1)
            calculatedNonce = challenge.calculateChallenge(nonce, AESKEY)
            if(calculatedNonce != receivedNonce or messageStatus != "ACCEPT_200"):
                print(f"{BRIGHT}{RED}An error occured with the connection! (Check Server)")
                print(Style.RESET_ALL)
                client.close()
                break
            return
        except Exception as e:
            print(e)
            print(f"{BRIGHT}{RED}An error occured with the connection!")
            print(Style.RESET_ALL)
            client.close()
            break

def receive():
    while True:
        try:
            message = client.recv(1024)
            message = aes_crypt.aes_decrypt(AESKEY, message).decode(FORMAT)
            integrityCheck = checkMessageIntegrity(message)
            if integrityCheck != 1:
                continue
            messageList = message.split(" ")
            sentHashValue = re.search(r'<(.*?)>', messageList[-1]).group(1)
            messageWithoutHash = message.replace(f'<{sentHashValue}>', "")[:-1]
            print(messageWithoutHash)
        except:
            # Close Connection When Error
            print("An error occured!")
            client.close()
            break

def write():
    while True:
        message = 'MESSAGE {}: {}'.format(nickname, input(''))
        HMAC = hashing.hash_sha256(message)
        messageWithHMAC = message + f' <{HMAC}>'
        cipherText = aes_crypt.aes_encrypt(AESKEY, messageWithHMAC.encode(FORMAT))
        client.send(cipherText)

def checkMessageIntegrity(message):
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
