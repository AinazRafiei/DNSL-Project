import socket
import os
from _thread import *
import rsa
from rsa import PrivateKey
import random
from datetime import datetime
import cryptocode
from cryptography.fernet import Fernet
# parameters
ServerSideSocket = socket.socket()
host = '127.0.0.1'
port = 2007
ThreadCount = 0
n = 19353072620215321890839106022762029874616444235223439384506680940328852784978944046938103327486305810943210038928498151161647567462545656069589447664175635864396307015807038943684431276693891870148118064557942055262537592536473689018920503531669331200322024475788186288928089621311451340215661550795441132293506814104945114183179870123103367402186037768285692824100462386028418539438996322154955270951250426145331720494910074450045563758975875988516544606871828721995156329535934701683337599110480406936432698277598516793178769767606955270092448746018533912221109558391545108250523168726755208689630948683233423809683
e = 65537
d = 5099830083023614279792962158980427177542853532238411861550427694881964197271562074715367570466888953644341934667365962289419007432109548504231346585292479536416439906663221730586235685925561325624578466742689767526496852512396060383550621725009221505860221900557882985333294288112802915078120647782883531650896025130264382290655376277635451623703139522651879483217140104843031673785959315978185610530216273214515508910534505539058349732206073386041695249200630328628046330672918849139116111945933814363365876052156083216049410406647494873120540717832080613961335158983453445837159202960545885645929103114295924224353
p = 2876785668235688529478279133194284873232123972958953088091648131776598542717174150037901813176994888392395459798557603145387332504317389542428948390411717697277214661633264566620938362402016006786107192939389704416148543673321514390656062738581223250151588818476296000386042935106541212214625181212135201168279450748153747548379
q = 6727325164993754590472155557373048516947121277270240743158602768793143097175515665856205739886263974595939838767433826791467666902622647134711749802645816146202460102725653769160273954007562580274287236295166212199060447254972874360600942086475321639262047478412960180456556950620383505577
P = 467
g = 5
###################
prv = PrivateKey(n, e, d, p, q)
# username: [hash(password) - connection object - pub. key - online state - mailbox list]
users = {}

try:
    ServerSideSocket.bind((host, port))
except socket.error as e:
    print(str(e))
print('Socket is listening..')
ServerSideSocket.listen(5)

def check_sign(message, hash, pub):
    try:
        a = rsa.verify(message.encode(), bytes.fromhex(hash), pub)
        print(a)
        return True
    except:
        print('verification failed')
        return False

def rsa_encrypt(message, pub):
    result = []
    for n in range(0, len(message), 245):
        result.append(rsa.encrypt(message[n:n + 245].encode(), pub))
    
    return b''.join(result)


def rsa_decrypt(content, prv):
    result = []
    for n in range(0, len(content), 256):
        result.append(rsa.decrypt(content[n:n + 256], prv).decode())
    
    return ''.join(result)


def register(command, connection):
    # phase 2
    rand2 = random.randint(1, P)
    dh_2 = (g**rand2) % P
    ts = datetime.now().strftime('%H:%M')

    if command[1] in users:
        pass
    else:
        # phase 3
        message = f'register-{command[1]}-{dh_2}-' + ts
        sign = rsa.sign(message.encode(), prv, 'SHA-256').hex()
        message = message + '-' + sign
        connection.send(cryptocode.encrypt(message, command[2]).encode())
        data = connection.recv(4096)

        #phase 5
        key = str(int(command[3])**rand2%P)
        encrypted, hash = data.decode().split('||')
        message = cryptocode.decrypt(encrypted, key)
        splitted_message = message.split('-')
        my_hash = rsa.compute_hash(message.encode(), 'SHA-256')
        
        if my_hash.hex() == hash:
            user_public_key = rsa.PublicKey(int(splitted_message[2]), int(splitted_message[3]))
            users[splitted_message[1]] = [rsa.compute_hash(command[2].encode(), 'SHA-256'), connection, user_public_key, 0, []]

def login(command, connection):
    print('hello')
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    if command[1] not in users:
        result = 'there is no user with this username'
    elif users[command[1]][0] != rsa.compute_hash(command[2].encode(), 'SHA-256'):
        result = 'password is wrong'
    else:
        if check_sign(message, sign, users[command[1]][2]):
            users[command[1]][3] = 1
            users[command[1]][1] = connection
            result = 'you logged in'

    ts = datetime.now().strftime('%H:%M')
    plaintext = 'login-' + result + '-' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '-' + sign

    connection.send(rsa_encrypt(message, users[command[1]][2]))

def show_onlines(command, connection):
    message = '-'.join(command[len(command) - 1])
    sign = command[-1]
    result = 'nothing'

    if command[1] not in users:
        result = 'there is no user with this username'
    elif users[command[1]][3] == 0:
        result = 'you must login first'
    else:
        result = 'online_users:'
        for user in users:
            if users[user][3] == 1:
                result = result + user + '\\'

    ts = datetime.now().strftime('%H:%M')
    plaintext = 'show_onlines-' + result + '-' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '-' + sign

    connection.send(rsa_encrypt(message, users[command[1]][2]))


def new_connection(command, connection):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    ts = datetime.now().strftime('%H:%M')


    if command[1] not in users or command[2] not in users:
        result = 'one of the users is not in system'
    elif check_sign(message, sign, users[command[1]][2]):
        print('sign ok')
        conn_key = Fernet.generate_key().decode()
        result = f'connection key: {conn_key}'

        plaintext2 = f'new_connection-{command[1]}-{command[2]}-connection key:{conn_key}-' + ts
        sign2 = rsa.sign(plaintext2.encode(), prv, 'SHA-256').hex()
        message2 = plaintext2 + '-' + sign2

        users[command[2]][4].append(rsa_encrypt(message2, users[command[2]][2]))
        print('message in mailbox')
    
    plaintext = f'new_connection-{command[1]}-{command[2]}-{result}-{command[3]}-' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '-' + sign
    connection.send(rsa_encrypt(message, users[command[1]][2]))

def check_mailbox(command, connection):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    ts = datetime.now().strftime('%H:%M')
    state = 0
    print('fuck you')
    if command[1] not in users:
        result = 'there is no user with this username'
        state = 1
    elif len(users[command[1]][4]) == 0:
        result = 'you dont have any message'
        state = 1
    
    if state == 1:
        plaintext = result + '-' + ts
        sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
        message = plaintext + '-' + sign
        connection.send(rsa_encrypt(message, users[command[1]][2]))
    else:
        if check_sign(message, sign, users[command[1]][2]):
            message = users[command[1]][4].pop(0)
            connection.send(message)



def run_command(command, connection):
    if command[0] == 'register':
        print('hello')
        register(command, connection)
    elif command[0] == 'login':
        print('hy')
        login(command, connection)
    elif command[0] == 'show_onlines':
        show_onlines(command, connection)
    elif command[0] == 'new_connection':
        new_connection(command, connection)
    elif command[0] == 'check_mailbox':
        check_mailbox(command, connection)

def multi_threaded_client(connection):
    connection.send(str.encode('Server is working:'))
    while True:
        data = connection.recv(2048)
        message = rsa_decrypt(data, prv)
        print(message)
        command = message.split('-')
        run_command(command, connection)
    connection.close()


while True:
    Client, address = ServerSideSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(multi_threaded_client, (Client,))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))
ServerSideSocket.close()
