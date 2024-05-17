# Secure Chat Room Server

This project is about setting up a secure chat room server that can handle multiple client connections. The server receives messages from clients, encrypts them, and broadcasts them to all connected clients. It also maintains a list of users and stores all messages in a JSON file.

## Project Overview

The server is designed to handle multiple clients simultaneously, each in its own thread. It uses SSL for secure communication between the server and clients. Each client message is encrypted using the receiver’s public key and can only be decrypted using the corresponding private key.

When a client connects to the server, they are prompted to enter a username and password. If the username is already stored in the users.json file, the client must provide the correct password associated with that username to connect to the chat room. If the username is not already stored, a new entry is created in the users.json file with the provided username and password.

Once connected, clients can send messages to every other client connected to the server. All messages are stored in the message_history.json file.

## Initial Setup

Before starting the server, two JSON files need to be set up:

- `message_history.json`: This file will store all the messages received from the clients. The initial value should be an empty JSON object `{}`.
- `users.json`: This file will store the list of users. The initial value should be a JSON object with an empty list for the key “users”, i.e., `{ "users": [] }`.

## Starting the Server

The server should be started first before any clients attempt to connect. The server will listen for incoming client connections and handle their messages.

## Dependencies

The project has a couple of dependencies that need to be installed. You can install them using pip:

```bash
pip install cryptography
pip install requests
pip install tk
```

## Security Considerations

An attacker could potentially gain access to the chat room by guessing the password associated with a username. This can be done through a brute force attack or a common password attack. Once the attacker gains access to the chat room, they can listen to all communication security measures to protect against these types of attacks. 
