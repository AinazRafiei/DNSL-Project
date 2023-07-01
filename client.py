import socket
from rsa import PublicKey
import rsa
import random
from datetime import datetime
import cryptocode
from cryptography.fernet import Fernet
# parameters
host = '127.0.0.1'
port = 2006
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
        rsa.verify(message.encode(), bytes.fromhex(hash), pub)
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

        
def register(command):
    # phase 1
    rand1 = random.randint(1, P)
    dh_1 = (g**rand1) % P
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')

    message = f'register-{command[1]}-{command[2]}-{dh_1}-' + ts
    ClientMultiSocket.send(rsa_encrypt(message, pub))

    # phase 4
    response = ClientMultiSocket.recv(2048).decode()
    password = input('password: ')
    message = cryptocode.decrypt(response, password).split('-')
    main_message = '-'.join(message[:len(message)-1])

    if check_server_sign(main_message, message[-1]):
        
        if 'register' in main_message and message[1] == command[1] and check_ts(message[3]):
            key = str((int(message[2])**rand1)%P)
        
            p1, p2 = rsa.newkeys(2048)
            # set client private key
            global my_private
            my_private = p2
            
            ts = datetime.now().strftime('%Y_%m_%d %H:%M')
            plaintext = f'register-{message[1]}-{p1.n}-{p1.e}-' + ts
            message = cryptocode.encrypt(plaintext, key)
            hash1 = rsa.compute_hash(plaintext.encode(), 'SHA-256').hex()
            message = message + '||' + hash1
            
            ClientMultiSocket.send(message.encode())
            print('register successfully done')
        else:
            print(main_message)

def login(command):
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = f'login-{command[1]}-{command[2]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign
    
    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('-')

    message = '-'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign) and check_ts(splitted_message[2]):
        print(message)

def show_onlines(command):
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = f'show_onlines-{command[1]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign
    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('-')

    message = '-'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign) and check_ts(splitted_message[2]):
        print(message)

def new_connection(command):
    nonce = random.randint(1, 100000)
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')

    plaintext = f'new_connection-{command[1]}-{command[2]}-{nonce}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign

    ClientMultiSocket.send(rsa_encrypt(message, pub))

    
    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('||')

    message = '||'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]
   
    if check_server_sign(message, sign) and check_ts(splitted_message[5]):
        if 'connection key' in message:
            key = splitted_message[3].split(':')[1].encode()
            connection_keys[splitted_message[2]] = [key, 0]
            print(f'you have new connection with {splitted_message[2]} with main key: {key}')
        else:
            print(splitted_message[3])
            print(f'time: {splitted_message[5]}')

def set_key(command, username):
    message = '-'.join(command).split('||')

    main_message = '||'.join(message[:len(message) - 1])
    sign = message[-1]
    
    if check_server_sign(main_message, sign) and message[2] == username and check_ts(message[4]):
        key = message[3].split(':')[1].encode()
        connection_keys[message[1]] = [key, 0]
        print(f'{message[1]} set a new connection with you with key: {key}')
        print(f'time: {message[4]}')
        
def get_message(command, username):
    splitted_message = '-'.join(command).split('||')
    message = '||'.join(splitted_message[:len(splitted_message)-1])
    my_username = splitted_message[0].split('-')[-1]
    encrypted_message = splitted_message[1]
    sign = splitted_message[-1]
    
    
    
    if command[1] in connection_keys:
        key, seq = connection_keys[command[1]]
        
        f = Fernet(key)
        main_message = f.decrypt(encrypted_message.encode()).decode().split('-')
        
        if check_server_sign(message, sign) and username == my_username and main_message[0] == command[1] and int(main_message[2]) == seq and main_message[3] == 'personal_message' and check_ts(main_message[4]):
            connection_keys[command[1]][1] += 1
            print(f'you have a new message from {command[1]} at {message[len(message) - 16: len(message)]}')
            print('content:')
            print(main_message[1])
            
            with open("{}-mailbox.txt".format(my_username), 'a') as f:
                f.write(f' message from {command[1]} at {message[len(message) - 16: len(message)]}')
                f.write('content:')
                f.write(main_message[1])
                f.write('---------------------------------------------------------------------------')
            
            
        else:
            print('you got an insecure message')

def set_group(command, username):
    text = '-'.join(command)

    main_commands = text.split('||')
    message = '||'.join(main_commands[:len(main_commands)-1])
    sign = main_commands[-1]


    if check_server_sign(message, sign) and check_ts(main_commands[-2]) and username == main_commands[2]:
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
        
        if decrypted_message[0] == main_commands[1] and decrypted_message[1] == main_commands[2] and  check_ts(decrypted_message[3]) and decrypted_message[4] == 'group_message':
            print('you have new group message')
            print(f'group: {main_commands[2]}')
            print(f'send by: {decrypted_message[0]}')
            print(f'time: {decrypted_message[3]}')
            print(f'content: {decrypted_message[2]}')
            
            with open("{}-{}-messages.txt".format(main_commands[1], main_commands[2]), 'a') as f:
                f.write(f'group: {main_commands[2]}')
                f.write(f'send by: {decrypted_message[0]}')
                f.write(f'time: {decrypted_message[3]}')
                f.write(f'content: {decrypted_message[2]}')
                f.write('-----------------------------------------')
                

def delete(command, username):
    main_message = '-'.join(command)

    main_commands = main_message.split('||')
    message = '||'.join(main_commands[:len(main_commands)-1])
    sign = main_commands[-1]

    if check_server_sign(message, sign) and main_commands[2] == username and check_ts(main_commands[-2]):
        print(f'you are deleted from group {main_commands[3]} by user {main_commands[1]}')
        print(f'time: {main_commands[4]}')
        del group_keys[main_commands[3]]

def new_group_key(command, username):
    main_message = '-'.join(command)

    main_commands = main_message.split('||')
    message = '||'.join(main_commands[:len(main_commands)-1])
    sign = main_commands[-1]

    if check_server_sign(message, sign) and main_commands[2] == username and main_commands[3] in group_keys and check_ts(main_commands[-2]):
        key = main_commands[4].encode()
        print(f'group key of {main_commands[3]} changed by user {main_commands[1]} and new key is {key}')
        print(f'time: {main_commands[5]}')
        group_keys[main_commands[3]] = key

def process_input(command, username):
    if command[0] == 'new_connection':
        set_key(command, username)
    elif command[0] == 'send_message':
        get_message(command, username)
    elif command[0] == 'add_member':
        set_group(command, username)
    elif command[0] == 'group_message':
        send_group_message(command)
    elif command[0] == 'delete_member':
        delete(command, username)
    elif command[0] == 'new_group_key':
        new_group_key(command, username)



def check_mailbox(command):
    username = command[1]

    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = f'check_mailbox-{command[1]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign

    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    response = rsa_decrypt(data, my_private)

    if 'there is no user with this username' in response or 'you dont have any message' in response or 'you must login first' in response:
        print(response)
    else:
        
        command = response.split('-')
        process_input(command, username)

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
    print('send message to another user:')
    print('send_message <your_usrename> <another_username> <message>')
    print('create new group:')
    print('create_group <your_username> <group_name>')
    print('add a new user to group:')
    print('add_member <your_username> <another_username> <group_name>')
    print('send a message to all members in a group:')
    print('group_message <your_username> <group_name> <message>')
    print('delete a member from group:')
    print('delete_member <your_username> <another_username> <group_name>')
    print('show_pv <username>')
    print('show_group <username> <group>')

def send_message(command):
    if command[2] not in connection_keys:
        print('you dont have any connection with another user')
    else:
        ts = datetime.now().strftime('%Y_%m_%d %H:%M')
        key, seq = connection_keys[command[2]]
        
        f = Fernet(key)
        encrypted_message = f.encrypt(f'{command[1]}-{command[3]}-{seq}-personal_message-{ts}'.encode()).decode()
        plaintext = f'send_message-{command[1]}-{command[2]}||{encrypted_message}||' + ts
        sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
        message = plaintext + '||' + sign
        connection_keys[command[2]][1] += 1

        ClientMultiSocket.send(rsa_encrypt(message, pub))

        data = ClientMultiSocket.recv(2048)
        response = rsa_decrypt(data, my_private)
        
        message = '-'.join(response.split('-')[:len(response.split('-')) - 1])
        sign = response.split('-')[-1]
        
        if check_server_sign(message, sign) and check_ts(response.split('-')[-2]):
            print(message)

def create_group(command):
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
    plaintext = f'create_group-{command[1]}-{command[2]}-' + ts
    sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
    message = plaintext + '-' + sign

    ClientMultiSocket.send(rsa_encrypt(message, pub))

    data = ClientMultiSocket.recv(2048)
    splitted_message = rsa_decrypt(data, my_private).split('||')

    message = '||'.join(splitted_message[:len(splitted_message) - 1])
    sign = splitted_message[-1]

    if check_server_sign(message, sign) and check_ts(splitted_message[-2]):
        if 'group_key' in message and splitted_message[1] == command[2]:
            key = splitted_message[2].split(':')[1].encode()
            group_keys[command[2]] = key
            print(f'the group \"{splitted_message[1]}\" is created. admin: {splitted_message[0]} with key: {key}')
        else:
            print(message.replace('||', ' '))


# add_member-user1-user2-group-key-ts
def add_member(command):
    if command[3] not in group_keys:
        print('you are not in this group')
    else:
        ts = datetime.now().strftime('%Y_%m_%d %H:%M')
        key = group_keys[command[3]].decode()

        plaintext = f'add_member-||{command[1]}||{command[2]}||{command[3]}||{key}||{ts}'
        sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
        message = plaintext + '||' + sign

        ClientMultiSocket.send(rsa_encrypt(message, pub))

        data = ClientMultiSocket.recv(2048)
        splitted_message = rsa_decrypt(data, my_private).split('-')

        message = '-'.join(splitted_message[:len(splitted_message) - 1])
        sign = splitted_message[-1]

        if check_server_sign(message, sign) and check_ts(splitted_message[-2]):
            print(message)


# group_message <sender> <group_name> <message>
def group_message(command):
    ts = datetime.now().strftime('%Y_%m_%d %H:%M')
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

        if check_server_sign(message, sign) and check_ts(splitted_message[-2]):
            print(message)

# delete_member-admin-user-group
def delete_member(command):
    if command[3] not in group_keys:
        print('you are not in this group')
    else:
        ts = datetime.now().strftime('%Y_%m_%d %H:%M')

        plaintext = f'delete_member-||{command[1]}||{command[2]}||{command[3]}||{ts}'
        sign = rsa.sign(plaintext.encode(), my_private, 'SHA-256').hex()
        message = plaintext + '||' + sign

        ClientMultiSocket.send(rsa_encrypt(message, pub))

        data = ClientMultiSocket.recv(2048)
        splitted_message = rsa_decrypt(data, my_private).split('||')

        message = '||'.join(splitted_message[:len(splitted_message) - 1])
        sign = splitted_message[-1]

        if check_server_sign(message, sign) and check_ts(splitted_message[-2]):
            if 'group_key' in splitted_message[3]:
                if command[1] == splitted_message[0] and command[2] == splitted_message[1] and command[3] == splitted_message[2]:
                    key = splitted_message[3].split(':')[1].encode()
                    print(f'the member {splitted_message[1]} deleted from group {splitted_message[2]} and new key is {key}')
                    group_keys[command[3]] = key
            else:
                print(message.replace('||', '-'))


def show_pv_messages(command):
    # to do check Integrity of user to see the file
    
    with open("{}-mailbox.txt".format(command[1]), "r") as f:
        lines = f.readlines()
        for line in lines:
            print(line)
            
            
def show_group(command):
    # To Do chech Integrity of user
    
    with open("{}-{}-messages.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            print(line)



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
    elif command[0] == 'delete_member':
        delete_member(command)
    elif command[0] == 'show_pv':
        show_pv_messages(command)
    elif command[0] == 'show_group':
        show_group(command)


while True:
    Input = input()
    command = Input.split(' ')
    run_command(command)

ClientMultiSocket.close()
