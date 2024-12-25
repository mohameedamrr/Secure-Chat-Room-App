import os
import socket
import threading
from formats import MAGENTA,WHITE,Style,BLUE,RED,ITALIC,YELLOW,BRIGHT,GREEN,CYAN,MAGENTA_BG
import aes_crypt
import rsa_crypt
import challenge
from Crypto.Signature import pkcs1_15
from dotenv import load_dotenv, dotenv_values
import ast
from Crypto.Hash import SHA256

PUBLICKEY = None
PRIVATEKEYCLIENT = None
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

    salt = os.urandom(16)
    message = f'CREATE <{username}> <{password}> <{salt}>'
    delimiter = b":::DELIMITER:::"
    hashMessage = SHA256.new(message.encode(FORMAT))
    encryptedHash = pkcs1_15.new(PRIVATEKEYCLIENT).sign(hashMessage)
    encryptedMessage = aes_crypt.aes_encrypt(AESKEY, message.encode(FORMAT))
    newMesssage = encryptedMessage + delimiter + encryptedHash
    client.send(newMesssage)
    while True:
        try:
            message = client.recv(1024)
            delimiter = b":::DELIMITER:::"
            parts = message.split(delimiter)
            decryptedMessage = aes_crypt.aes_decrypt(AESKEY, parts[0]).decode(FORMAT)
            digitalSignature = parts[1]
            if not checkMessageIntegrity(decryptedMessage,digitalSignature):
                print(f"{BRIGHT}{RED}digital signature is different")
                print(Style.RESET_ALL)
                client.close()
                break
            if "ACCEPT 200" in decryptedMessage:
                isUserLoggedIn = True
                nickname = username
                print(f"{BRIGHT}{GREEN}Account Created Successfully!")
                print(Style.RESET_ALL)
                return
            elif "USERNAME_TAKEN 400" in decryptedMessage:
                print(f"{BRIGHT}{RED}The username already exists in the database, please try again.")
                print(Style.RESET_ALL)
                return
            elif "FAILED 500" in decryptedMessage:
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
    message = f'LOGIN <{username}> <{password}>'
    delimiter = b":::DELIMITER:::"
    hashMessage = SHA256.new(message.encode(FORMAT))
    encryptedHash = pkcs1_15.new(PRIVATEKEYCLIENT).sign(hashMessage)
    encryptedMessage = aes_crypt.aes_encrypt(AESKEY, message.encode(FORMAT))
    newMesssage = encryptedMessage + delimiter + encryptedHash
    client.send(newMesssage)
    while True:
        try:
            message = client.recv(1024)
            delimiter = b":::DELIMITER:::"
            parts = message.split(delimiter)
            decryptedMessage = aes_crypt.aes_decrypt(AESKEY, parts[0]).decode(FORMAT)
            digitalSignature = parts[1]
            if not checkMessageIntegrity(decryptedMessage,digitalSignature):
                print(f"{BRIGHT}{RED}digital signature is different")
                print(Style.RESET_ALL)
                client.close()
                break
            if "ACCEPT 200" in decryptedMessage:
                isUserLoggedIn = True
                nickname = username
                print(f"{BRIGHT}{GREEN}Login Success!")
                print(Style.RESET_ALL)
                return
            elif "NOT_FOUND 401" in decryptedMessage:
                print(f"{BRIGHT}{RED}The username does not exist in the database, please try again.")
                print(Style.RESET_ALL)
                return
            elif "INCORRECT_PASSWORD 402" in decryptedMessage:
                print(f"{BRIGHT}{RED}Incorrect Password Entered, please try again.")
                print(Style.RESET_ALL)
                return
            elif "FAILED 500" in decryptedMessage:
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
    global PUBLICKEY
    global PRIVATEKEYCLIENT
    global AESKEY
    message = 'CONNECT'
    nonce = challenge.generateNonce()
    AESKEY = aes_crypt.generate_aes_key()
    (private_key_client, public_key_client) = rsa_crypt.generate_rsa_keys()
    PRIVATEKEYCLIENT = private_key_client
    pem_public_key_client = rsa_crypt.key_to_pem(public_key_client, is_private=False)
    messageToEncrypt = message + f':::{AESKEY}' + f':::{nonce}'
    load_dotenv()
    PUBLICKEY = rsa_crypt.RSA.import_key(os.getenv("SERVER_PUBLIC_KEY"))
    encryptedMessage = rsa_crypt.rsa_encrypt(PUBLICKEY, messageToEncrypt.encode(FORMAT))
    delimiter = b":::DELIMITER:::"
    totalMessage = encryptedMessage + (f'{delimiter}{pem_public_key_client}').encode(FORMAT)
    client.send(totalMessage)
    while True:
        try:
            message = client.recv(1024)
            delimiter = b":::DELIMITER:::"
            parts = message.split(delimiter)
            decryptedMessage = rsa_crypt.rsa_decrypt(private_key_client, parts[0]).decode(FORMAT)
            messageList = decryptedMessage.split(":::DELIMITER:::")
            messageStatus = messageList[0]
            receivedNonce = ast.literal_eval(messageList[1])
            digitalSignature = parts[1]
            if not checkMessageIntegrity(decryptedMessage,digitalSignature):
                print(f"{BRIGHT}{RED}digital signature is different")
                print(Style.RESET_ALL)
                client.close()
                break
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
            delimiter = b":::DELIMITER:::"
            parts = message.split(delimiter)
            decryptedMessage = aes_crypt.aes_decrypt(AESKEY, parts[0]).decode(FORMAT)
            digitalSignature = parts[1]
            if not checkMessageIntegrity(decryptedMessage,digitalSignature):
                print(f"{BRIGHT}{RED}digital signature is different")
                print(Style.RESET_ALL)
                client.close()
                break
            newMessage = decryptedMessage.replace('MESSAGE ', "")
            print(newMessage)
        except:
            # Close Connection When Error
            print("An error occured!")
            client.close()
            break

def write():
    while True:
        message = 'MESSAGE {}: {}'.format(nickname, input(''))
        delimiter = b":::DELIMITER:::"
        hashMessage = SHA256.new(message.encode(FORMAT))
        encryptedHash = pkcs1_15.new(PRIVATEKEYCLIENT).sign(hashMessage)
        encryptedMessage = aes_crypt.aes_encrypt(AESKEY, message.encode(FORMAT))
        newMesssage = encryptedMessage + delimiter + encryptedHash
        client.send(newMesssage)

def checkMessageIntegrity(message , signature):
    global PUBLICKEY
    try:
        calculatedHash = SHA256.new(message.encode(FORMAT))
        pkcs1_15.new(PUBLICKEY).verify(calculatedHash,signature)
        return 1
    except Exception as e:
        print(e)
        return 0

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
