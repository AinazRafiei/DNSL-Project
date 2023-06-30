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
port = 2006
ThreadCount = 0
P = 467
g = 5
###################
password = input('private key password: ')
file = open('private_key.txt', 'r')
cipher = file.read()
file.close()

text = cryptocode.decrypt(cipher, password)

parameters = []
for x in text.split('\n'):
    parameters.append(int(x))

n, e, d, p, q = parameters
prv = PrivateKey(n, e, d, p, q)
# username: [hash(password) - connection object - pub. key - online state - mailbox list]
users = {}

#group_name: [admin_name, [member_name(s)]]
groups = {}
try:
    ServerSideSocket.bind((host, port))
except socket.error as e:
    print(str(e))
print('Socket is listening..')
ServerSideSocket.listen(5)

def check_sign(message, hash, pub):
    try:
        a = rsa.verify(message.encode(), bytes.fromhex(hash), pub)
        print('signature verified')
        return True
    except:
        print('verification failed')
        return False
    
def check_ts(ts):
    new_ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    split_ts = ts.split(' ')
    split_new_ts = new_ts.split(' ')

    if split_ts[0] == split_new_ts[0] and split_ts[1].split(':')[0] == split_new_ts[1].split(':')[0] and abs(int(split_ts[1].split(':')[1]) - int(split_new_ts[1].split(':')[1])) < 10:
        print('timestamp verified')
        return True
    else:
        print('timestamp verification failed')
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
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')

    if check_ts(command[4]):
        if command[1] in users:
            message = f'choose a new username-{ts}'
            sign = rsa.sign(message.encode(), prv, 'SHA-256').hex()
            message = message + '-' + sign
            connection.send(cryptocode.encrypt(message, command[2]).encode())
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
            
            if my_hash.hex() == hash and check_ts(splitted_message[4]):
                user_public_key = rsa.PublicKey(int(splitted_message[2]), int(splitted_message[3]))
                users[splitted_message[1]] = [rsa.compute_hash(command[2].encode(), 'SHA-256'), connection, user_public_key, 0, []]

def login(command, connection):
    
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    if command[1] not in users:
        result = 'there is no user with this username'
    elif users[command[1]][0] != rsa.compute_hash(command[2].encode(), 'SHA-256'):
        result = 'password is wrong'
    else:
        if check_sign(message, sign, users[command[1]][2]) and check_ts(command[3]):
            users[command[1]][3] = 1
            users[command[1]][1] = connection
            result = 'you logged in'

    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = 'login-' + result + '-' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '-' + sign

    connection.send(rsa_encrypt(message, users[command[1]][2]))

def show_onlines(command, connection):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    
    if command[1] not in users:
        result = 'there is no user with this username'
    elif users[command[1]][3] == 0:
        result = 'you must login first'
    elif check_sign(message, sign, users[command[1]][2]) and check_ts(command[2]):
        result = 'online_users:'
        for user in users:
            if users[user][3] == 1:
                result = result + user + '\\'

    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = 'show_onlines-' + result + '-' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '-' + sign

    connection.send(rsa_encrypt(message, users[command[1]][2]))


def new_connection(command, connection):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')


    if command[1] not in users or command[2] not in users:
        result = 'one of the users is not in system'
    elif users[command[1]][3] == 0:
        result = 'you must login first'
    elif check_sign(message, sign, users[command[1]][2]) and check_ts(command[4]):
        print('sign ok')
        conn_key = Fernet.generate_key().decode()
        result = f'connection key: {conn_key}'
        print(result)

        plaintext2 = f'new_connection-||{command[1]}||{command[2]}||connection key:{conn_key}||' + ts
        sign2 = rsa.sign(plaintext2.encode(), prv, 'SHA-256').hex()
        message2 = plaintext2 + '||' + sign2

        print(message2)
        users[command[2]][4].append(rsa_encrypt(message2, users[command[2]][2]))
        print('message in mailbox')
    
    plaintext = f'new_connection-||{command[1]}||{command[2]}||{result}||{command[3]}||' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '||' + sign
    connection.send(rsa_encrypt(message, users[command[1]][2]))

def check_mailbox(command, connection):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    state = 0
    
    if command[1] not in users:
        result = 'there is no user with this username'
        state = 1
    elif users[command[1]][3] == 0:
        result = 'you must login first'
    elif len(users[command[1]][4]) == 0:
        result = 'you dont have any message'
        state = 1
    
    if state == 1:
        plaintext = result + '-' + ts
        sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
        message = plaintext + '-' + sign
        connection.send(rsa_encrypt(message, users[command[1]][2]))
    else:
        if check_sign(message, sign, users[command[1]][2]) and check_ts(command[2]):
            message = users[command[1]][4].pop(0)
            connection.send(message)


def send_message(command, connection):
    splitted_message = '-'.join(command).split('||')
    message = '||'.join(splitted_message[:len(splitted_message)-1])
    receiver = splitted_message[0].split('-')[-1]
    sign = splitted_message[-1]
    result = 'nothing'
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')

    # and timestamp check
    if check_sign(message, sign, users[command[1]][2]) and check_ts(splitted_message[-2]):
        sign2 = rsa.sign(message.encode(), prv, 'SHA-256').hex()
        users[receiver][4].append(rsa_encrypt(message + '||' + sign2, users[receiver][2]))
        result = 'message in mailbox'
    else:
        result = 'there is a problem with sending the message'
    
    plaintext = result + '-' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '-' + sign
    print('||||||||||')
    print(message)
    connection.send(rsa_encrypt(message, users[command[1]][2]))

    
def create_group(command, connection):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    result = 'nothing'
    if users[command[1]][3] == 0:
        result = 'you must login first'
    elif check_sign(message, sign, users[command[1]][2]) and check_ts(command[3]):
        if command[2] in groups:
            result = 'the group name is already selected'
        else:
            group_key = Fernet.generate_key().decode()
            result = f'{command[1]}||{command[2]}||group_key:{group_key}'
            groups[command[2]] = [command[1], [command[1]]]

    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = result + '||' + ts
    sign = rsa.sign(plaintext.encode(), prv, 'SHA-256').hex()
    message = plaintext + '||' + sign

    connection.send(rsa_encrypt(message, users[command[1]][2]))

def add_member(command, connection):
    main_message = '-'.join(command)

    main_commands = main_message.split('||')
    message = '||'.join(main_commands[:len(main_commands)-1])
    sign = main_commands[-1]
    result = 'nothing'

    if users[main_commands[1]][3] == 0:
        result = 'you must login first'
    elif main_commands[2] not in users:
        result = 'there is no user with this username'
    elif not(main_commands[3] in groups):
        result = 'there is no group with this name'
    elif main_commands[1] != groups[main_commands[3]][0]:
        result = 'you are not the admin of group'
    elif main_commands[2] in groups[main_commands[3]][1]:
        result = 'the user is already added to group'
    elif check_sign(message, sign, users[main_commands[1]][2]) and check_ts(main_commands[5]):
        result = f'the user {main_commands[2]} added to group {main_commands[3]}'

        new_sign = rsa.sign(message.encode(), prv, 'SHA-256').hex()
        new_message = message + '||' + new_sign
        users[main_commands[2]][4].append(rsa_encrypt(new_message, users[main_commands[2]][2]))
        groups[main_commands[3]][1].append(main_commands[2])

    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    response = result + '-' + ts
    sign = rsa.sign(response.encode(), prv, 'SHA-256').hex()
    response_message = response + '-' + sign

    connection.send(rsa_encrypt(response_message, users[main_commands[1]][2]))


def group_message(command, connection):
    main_message = '-'.join(command)

    main_commands = main_message.split('||')
    message = '||'.join(main_commands[:len(main_commands) - 1])
    sign = main_commands[-1]
    result = 'nothing'

    if main_commands[2] not in groups:
        result = 'there is no group with this name'
    elif main_commands[1] not in groups[main_commands[2]][1]:
        result = 'you are not in this group'
    elif check_sign(message, sign, users[main_commands[1]][2]) and check_ts(main_commands[-2]):
        result = f'your message is sent in group {main_commands[2]}'

        new_sign = rsa.sign(message.encode(), prv, 'SHA-256').hex()
        new_message = message + '||' + new_sign
        
        for user in groups[main_commands[2]][1]:
            users[user][4].append(rsa_encrypt(new_message, users[user][2]))

        ts = datetime.now().strftime('%Y_%m_%d %H:%M')
        response = result + '-' + ts
        sign = rsa.sign(response.encode(), prv, 'SHA-256').hex()
        response_message = response + '-' + sign

        connection.send(rsa_encrypt(response_message, users[main_commands[1]][2]))

def delete_member(command, connection):
    main_message = '-'.join(command)
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    main_commands = main_message.split('||')
    message = '||'.join(main_commands[:len(main_commands) - 1])
    sign = main_commands[-1]
    result = 'nothing'

    if users[main_commands[1]][3] == 0:
        result = 'you must login first'
    elif main_commands[3] not in groups:
        result = 'there is no group with this name'
    elif main_commands[1] != groups[main_commands[3]][0]:
        result = 'you are not the admin of group'
    elif main_commands[2] not in groups[main_commands[3]][1]:
        result = 'there is no user with this username in this group'
    elif main_commands[1] == main_commands[2]:
        result = 'you cannot delete yourself!'
    elif check_sign(message, sign, users[main_commands[1]][2]) and check_ts(main_commands[-2]):
        # message for admin
        group_key = Fernet.generate_key().decode()
        result = f'{main_commands[1]}||{main_commands[2]}||{main_commands[3]}||group_key:{group_key}'
        groups[main_commands[3]][1].remove(main_commands[2])

        #message for deleted
        sign = rsa.sign(message.encode(), prv, 'SHA-256').hex()
        deleted_member_message = message + '||' + sign
        users[main_commands[2]][4].append(rsa_encrypt(deleted_member_message, users[main_commands[2]][2]))

        #message for other member
        for user in groups[main_commands[3]][1]:
            # not admin
            if user != main_commands[1]:
                other_member_message = f'new_group_key-||{main_commands[1]}||{user}||{main_commands[3]}||{group_key}||{ts}'
                sign = rsa.sign(other_member_message.encode(), prv, 'SHA-256').hex()
                message = other_member_message + '||' + sign
                users[user][4].append(rsa_encrypt(message, users[user][2]))

    response = result + '||' + ts
    sign = rsa.sign(response.encode(), prv, 'SHA-256').hex()
    response_message = response + '||' + sign

    connection.send(rsa_encrypt(response_message, users[main_commands[1]][2]))









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
    elif command[0] == 'send_message':
        send_message(command, connection)
    elif command[0] == 'create_group':
        create_group(command, connection)
    elif command[0] == 'add_member':
        add_member(command, connection)
    elif command[0] == 'group_message':
        group_message(command, connection)
    elif command[0] == 'delete_member':
        delete_member(command, connection)

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
