import socket
from rsa import PublicKey
import rsa
import random
from datetime import datetime
import cryptocode
from cryptography.fernet import Fernet
# parameters
host = '127.0.0.1'
port = 2007
n = 19353072620215321890839106022762029874616444235223439384506680940328852784978944046938103327486305810943210038928498151161647567462545656069589447664175635864396307015807038943684431276693891870148118064557942055262537592536473689018920503531669331200322024475788186288928089621311451340215661550795441132293506814104945114183179870123103367402186037768285692824100462386028418539438996322154955270951250426145331720494910074450045563758975875988516544606871828721995156329535934701683337599110480406936432698277598516793178769767606955270092448746018533912221109558391545108250523168726755208689630948683233423809683
e = 65537
g = 5
P = 467
my_private = None
########################################
# username: [key, seq_number]
connection_keys = {}

# groupname: key
group_keys = {}
ClientMultiSocket = socket.socket()
pub = PublicKey(n, e)
print('Waiting for connection response')
try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))
res = ClientMultiSocket.recv(1024)

def check_server_sign(message, hash):
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

        
def register(command):
    # phase 1
    rand1 = random.randint(1, P)
    dh_1 = (g**rand1) % P
    ts = datetime.now().strftime('%H:%M')

    message = f'register-{command[1]}-{command[2]}-{dh_1}-' + ts
    ClientMultiSocket.send(rsa_encrypt(message, pub))

    # phase 4
    response = ClientMultiSocket.recv(2048).decode()
    password = input('password: ')
    message = cryptocode.decrypt(response, password).split('-')
    main_message = '-'.join(message[:len(message)-1])

    if check_server_sign(main_message, message[-1]) and message[1] == command[1]:
        key = str((int(message[2])**rand1)%P)
        
        p1, p2 = rsa.newkeys(2048)
        # set client private key
        global my_private
        my_private = p2
        
        ts = datetime.now().strftime('%H:%M')
        plaintext = f'register-{message[1]}-{p1.n}-{p1.e}-' + ts
        message = cryptocode.encrypt(plaintext, key)
        hash1 = rsa.compute_hash(plaintext.encode(), 'SHA-256').hex()
        message = message + '||' + hash1
        
        ClientMultiSocket.send(message.encode())
        print('register successfully done')

def login(command):
    ts = datetime.now().strftime('%H:%M')
    plaintext = f'login-{command[1]}-{command[2]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign
    
    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('-')

    message = '-'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign):
        print(message)

def show_onlines(command):
    ts = datetime.now().strftime('%H:%M')
    plaintext = f'show_onlines-{command[1]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign
    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('-')

    message = '-'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign):
        print(message)

def new_connection(command):
    nonce = random.randint(1, 100000)
    ts = datetime.now().strftime('%H:%M')

    plaintext = f'new_connection-{command[1]}-{command[2]}-{nonce}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign

    ClientMultiSocket.send(rsa_encrypt(message, pub))

    
    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('-')

    message = '-'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign):
        if 'connection key' in message:
            key = message.split('||')[1].split(':')[1].encode()
            connection_keys[splitted_message[2]] = [key, 0]
            print(f'you have new connection with {splitted_message[2]} with main key: {key}')
        else:
            print(message)

def set_key(command):
    message = '-'.join(command[:len(command) - 1])
    sign = command[-1]
    
    if check_server_sign(message, sign):
        key = message.split('||')[1].split(':')[1].encode()
        connection_keys[command[1]] = [key, 0]
        print(f'{command[1]} set a new connection with you with key: {key}')
        print(f'time: {message[len(message) - 5: len(message)]}')
        
def get_message(command):
    splitted_message = '-'.join(command).split('||')
    message = '||'.join(splitted_message[:len(splitted_message)-1])
    my_username = splitted_message[0].split('-')[-1]
    encrypted_message = splitted_message[1]
    sign = splitted_message[-1]
    user = input('username: ')
    
    
    if command[1] in connection_keys:
        key, seq = connection_keys[command[1]]
        
        f = Fernet(key)
        main_message = f.decrypt(encrypted_message.encode()).decode().split('-')
        
        if check_server_sign(message, sign) and user == my_username and main_message[0] == command[1] and int(main_message[2]) == seq and main_message[3] == 'personal_message':
            connection_keys[command[1]][1] += 1
            print(f'you have a new message from {command[1]} at {message[len(message) - 5: len(message)]}')
            print('content:')
            print(main_message[1])
        else:
            print('you got an insecure message')

def set_group(command):
    text = '-'.join(command)

    main_commands = text.split('||')
    message = '||'.join(main_commands[:len(main_commands)-1])
    sign = main_commands[-1]

    username = input('username: ')

    if check_server_sign(message, sign) and username == main_commands[2]:
        group_keys[main_commands[3]] = main_commands[4].encode()
        print(f'you are added to group {main_commands[3]}  by user {main_commands[1]} with key:{main_commands[4].encode()}')

def send_group_message(command):
    main_message = '-'.join(command)

    main_commands = main_message.split('||')
    message = '||'.join(main_commands[:len(main_commands)-1])
    sign = main_commands[-1]

    key = group_keys[main_commands[2]]
    f = Fernet(key)

    if check_server_sign(message, sign):
        decrypted_message = f.decrypt(main_commands[3].encode()).decode().split('-')
        
        if decrypted_message[0] == main_commands[1] and decrypted_message[1] == main_commands[2] and decrypted_message[4] == 'group_message':
            print('you have new group message')
            print(f'group: {main_commands[2]}')
            print(f'send by: {decrypted_message[0]}')
            print(f'time: {decrypted_message[3]}')
            print(f'content: {decrypted_message[2]}')


def process_input(command):
    if command[0] == 'new_connection':
        set_key(command)
    elif command[0] == 'send_message':
        get_message(command)
    elif command[0] == 'add_member':
        set_group(command)
    elif command[0] == 'group_message':
        send_group_message(command)



def check_mailbox(command):
    ts = datetime.now().strftime('%H:%M')
    plaintext = f'check_mailbox-{command[1]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign

    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    response = rsa_decrypt(data, my_private)

    if 'there is no user with this username' in response or 'you dont have any message' in response:
        print(response.split('-')[0])
    else:
        command = response.split('-')
        process_input(command)

def help():
    print('register new user:')
    print('register <username> <password>')
    print('login:')
    print('login <username> <password>')
    print('show online(logged-in) memebers:')
    print('show_onlines <your_username>')
    print('create new connection with another user:')
    print('new_connection <your_username> <another_username>')
    print('check mailbox:')
    print('check_mailbox <your_username>')

def send_message(command):
    if command[2] not in connection_keys:
        print('you dont have any connection with another user')
    else:
        ts = datetime.now().strftime('%H:%M')
        key, seq = connection_keys[command[2]]
        
        f = Fernet(key)
        encrypted_message = f.encrypt(f'{command[1]}-{command[3]}-{seq}-personal_message'.encode()).decode()
        plaintext = f'send_message-{command[1]}-{command[2]}||{encrypted_message}||' + ts
        sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
        message = plaintext + '||' + sign
        connection_keys[command[2]][1] += 1

        ClientMultiSocket.send(rsa_encrypt(message, pub))

        data = ClientMultiSocket.recv(2048)
        response = rsa_decrypt(data, my_private)
        
        message = '-'.join(response.split('-')[:len(response.split('-')) - 1])
        sign = response.split('-')[-1]
        
        if check_server_sign(message, sign):
            print(message)

def create_group(command):
    ts = datetime.now().strftime('%H:%M')
    plaintext = f'create_group-{command[1]}-{command[2]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign

    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('||')

    message = '||'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign):
        if 'group_key' in message and splitted_message[1] == command[2]:
            key = splitted_message[2].split(':')[1].encode()
            group_keys[command[2]] = key
            print(f'the group \"{splitted_message[0]}\" is created. admin: {splitted_message[0]} with key: {key}')
        else:
            print(message.replace('||', ' '))


def add_member(command):
    if command[3] not in group_keys:
        print('there is no group with this name')
    else:
        ts = datetime.now().strftime('%H:%M')
        key = group_keys[command[3]].decode()

        plaintext = f'add_member-||{command[1]}||{command[2]}||{command[3]}||{key}||{ts}'
        sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
        message = plaintext + '||' + sign

        ClientMultiSocket.send(rsa_encrypt(message, pub))

        data = ClientMultiSocket.recv(2048)
        splitted_message = rsa_decrypt(data, my_private).split('-')

        message = '-'.join(splitted_message[:len(splitted_message) - 1])
        sign = splitted_message[-1]

        if check_server_sign(message, sign):
            print(message)


# groyp_message <sender> <group_name> <message>
def group_message(command):
    ts = datetime.now().strftime('%H:%M')
    if command[2] not in group_keys:
        print('you are not in this group')
    else:
        main_message = f'{command[1]}-{command[2]}-{command[3]}-{ts}-group_message'
        f = Fernet(group_keys[command[2]])
        encrypted = f.encrypt(main_message.encode()).decode()

        plaintext = f'group_message-||{command[1]}||{command[2]}||{encrypted}||{ts}'
        sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()

        message = plaintext + '||' + sign
        ClientMultiSocket.send(rsa_encrypt(message, pub))

        data = ClientMultiSocket.recv(2048)
        splitted_message = rsa_decrypt(data, my_private).split('-')

        message = '-'.join(splitted_message[:len(splitted_message) - 1])
        sign = splitted_message[-1]

        if check_server_sign(message, sign):
            print(message)


def run_command(command):
    if command[0] == 'register':
        register(command)
    elif command[0] == 'login':
        login(command)
    elif command[0] == 'show_onlines':
        show_onlines(command)
    elif command[0] == 'new_connection':
        new_connection(command)
    elif command[0] == 'check_mailbox':
        check_mailbox(command)
    elif command[0] == 'help':
        help()
    elif command[0] == 'send_message':
        send_message(command)
    elif command[0] == 'create_group':
        create_group(command)
    elif command[0] == 'add_member':
        add_member(command)
    elif command[0] == 'group_message':
        group_message(command)


while True:
    Input = input()
    command = Input.split(' ')
    run_command(command)

ClientMultiSocket.close()
