import socket
import threading
from formats import MAGENTA,WHITE,Style,BLUE,RED,ITALIC,YELLOW,BRIGHT,GREEN,CYAN,MAGENTA_BG
import hashlib
import re

# Choosing Nickname
nickname = ""

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('3.125.188.168', 17126))

isUserLoggedIn = False

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
    client.send(message.encode('utf-8'))
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
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

# Listening to Server and Sending Nickname
def receive():
    while True:
        # try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            message = client.recv(1024).decode('utf-8')
            if message == 'NICK':
                client.send(nickname.encode('utf-8'))
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
        client.send(message.encode('utf-8'))
        print(message)


if __name__ == "__main__":
    resposne = sendLoginRequest()
    if isUserLoggedIn:
        print(222222)
        # Starting Threads For Listening And Writing
        receive_thread = threading.Thread(target=receive)
        receive_thread.start()

        write_thread = threading.Thread(target=write)
        write_thread.start()