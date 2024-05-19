import threading
import socket
import ssl
import json
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import rsa
import datetime
import sys

host = '127.0.0.1'
port = 12345

# Create a SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='./server.crt', keyfile='./server.key')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

# Wrap the server socket with SSL
server = context.wrap_socket(server, server_side=True)

clients = []
aes_keys = {}  # Dictionary to store AES keys for each client

# Generate RSA keys
private_key, public_key = rsa.generate_rsa_keys()

# Serialize public key
serialized_public_key = rsa.serialize_public_key(public_key)


message_history = {}

def broadcast(message):
    for client in clients:  # Don't send the message back to the sender
        aes_key = aes_keys[client]
        encrypted_message = rsa.encrypt_message(message, aes_key)
        client.send(encrypted_message)

def handle_client(client):
    try:
        while True:
            aes_key = aes_keys[client]  # Retrieve the correct AES key for the client
            encrypted_message = client.recv(1024)
            message = rsa.decrypt_message(encrypted_message, aes_key)
            if message:
                print(f"Received message: {message}")
                timestamp = datetime.datetime.now().isoformat()
                message_history[timestamp] = message.decode()
                # Write the message history to the JSON file
                with open('message_history.json', 'w') as file:  # Open the file in write mode
                    json.dump(message_history, file)  # Write the entire message history
                broadcast(message.decode())  # Broadcast the encrypted message to all clients
            else:
                print("Error in message decryption or message integrity check failed.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the client socket is closed
        client.close()
        # Remove the client from the clients list if it exists
        if client in clients:
            clients.remove(client)
            del aes_keys[client]  # Remove the AES key associated with this client
        print(clients)
        # print(aes_keys)


# Create a hashed password
def create_hashed_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derives a key from the password
    storage_format = {"salt": base64.b64encode(salt).decode(
        'utf-8'), "key": base64.b64encode(key).decode('utf-8')}
    return storage_format

# Verify a password against a hash
def verify_password(stored_password, provided_password):
    salt = base64.b64decode(stored_password['salt'])
    key = base64.b64decode(stored_password['key'])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(provided_password.encode(), key)
        return True  # The password is correct
    except Exception:
        return False  # The password is incorrect

# Main function to receive the clients connection
def receive():
    while True:
        print('Server is running and listening ...')
        client, address = server.accept()
        print(f'connection is established with {str(address)}')

        client.send(serialized_public_key)
        # Receive encrypted AES key from client
        encrypted_aes_key = client.recv(1024)
        # Decrypt AES key
        aes_key = rsa.decrypt_aes_key(private_key, encrypted_aes_key)
        aes_keys[client] = aes_key  # Store the AES key for the client
        # print(aes_keys)

        while True:
            username = client.recv(1024).decode('utf-8') 
            password = client.recv(1024).decode('utf-8')
            # Load existing users
            with open('users.json', 'r') as file:
                users = json.load(file)
            user_entry = next((user for user in users['users'] if user["username"] == username), None)
            if user_entry:
                if verify_password(user_entry, password):
                    client.send('you are now connected!\n'.encode('utf-8'))
                    break
                else:
                    client.send('Incorrect password! Please try again.'.encode('utf-8'))
            else:
                # Add new user and save
                hashed_password = create_hashed_password(password)
                users['users'].append({"username": username, "salt": hashed_password["salt"], "key": hashed_password["key"]})
                with open('users.json', 'w') as file:
                    json.dump(users, file)
                client.send('you are now connected!\n'.encode('utf-8'))
                break
        clients.append(client)
        # print(clients)
        print(f'The username of this client is {username}'.encode('utf-8'))
        broadcast(f'{username} has connected to the chat room\n')
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()




if __name__ == "__main__":
    receive()

