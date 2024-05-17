# client.py
import socket
import tkinter as tk
import threading
import ssl
import rsa
from queue import Queue
import json


# Define username and root2 as global variables
username = None
root2 = None
root = None
chat_box = None
message_box = None

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

message_queue = Queue()



def client_receive():
    global username
    global root2
    global chat_box
    global root
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            message = rsa.decrypt_message(encrypted_message, aes_key) 
            chat_box.config(state=tk.NORMAL)  
            chat_box.insert(tk.END, message)
            chat_box.config(state=tk.DISABLED)  
                  
        except Exception as e:
            print('Error!')
            print(f'Exception type: {type(e)}')
            print(f'Exception message: {e}')
            root2.destroy()
            client_socket.close()
            break

def client_send(event=None):
    global username
    message = message_box.get()
    if message.strip():
        # Push message onto the queue
        message_queue.put(message)
        message_box.delete(0,tk.END)
    else:
        print("Cannot send an empty message.")

def send_thread_func():
    while True:
        message = message_queue.get()
        sending_message = f"{username}: {message}\n"
        encrypted_message = rsa.encrypt_message(sending_message, aes_key)
        client_socket.send(encrypted_message)



def password_strength(password):
    if len(password) < 6:
        return "weak"
    elif len(password) < 10:
        return "medium"
    elif any(char.isdigit() for char in password) and any(char.isalpha() for char in password):
        return "strong"
    else:
        return "weak"
        



def enter_username():
    global root
    global username
    try:
        root = tk.Tk()
        root.title("Sign-up/Sign-in")
        root.geometry("400x100")
        label1 = tk.Label(root, text="Please enter your username:")
        label1.pack(pady=5)
        entry1 = tk.Entry(root)
        entry1.pack(pady=5, padx=10, fill="x")
        label2 = tk.Label(root, text="Please enter your password:")
        label2.pack(pady=5)
        entry2 = tk.Entry(root, show="*")
        entry2.pack(pady=5, padx=10, fill="x")
        strength_label = tk.Label(root, text="")
        strength_label.pack(pady=5)

        #password strength function
        def check_strength(event):
            password = entry2.get()
            strength = password_strength(password)
            strength_label.config(text=f"Password strength: {strength.upper()}")
            if strength == "weak":
                strength_label.config(fg="red")
            elif strength == "medium":
                strength_label.config(fg="orange")
            else:
                strength_label.config(fg="green")        


        entry2.bind('<KeyRelease>', check_strength)
        button = tk.Button(root, text="Enter", command=lambda: set_username(entry1.get(), entry2.get()))
        button.pack(pady=5)
        root.bind('<Return>', lambda event: set_username(entry1.get(), entry2.get()))
        root.mainloop()
    except:
        root.destroy()
        client_socket.close()

def set_username(name, password):
    global username
    global root
    if name.strip() and password.strip():
        username = name
        password = password
        client_socket.send(username.encode('utf-8'))
        client_socket.send(password.encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        if response == 'you are now connected!\n':
            root.destroy()
        else:
            print(response)
            root.destroy()
            enter_username()
    else:
        print("Cannot send an empty username.")


def on_closing():
    global username
    message = f"{username} has left the chat\n"
    encrypted_message = rsa.encrypt_message(message, aes_key)
    client_socket.send(encrypted_message)
    root2.destroy()
    client_socket.close()

def view_message_history():
    # Create a new window
    history_window = tk.Toplevel(root2)
    history_window.title("Message History")

    # Create a Text widget in the new window
    history_box = tk.Text(history_window, width=100, height=20)
    history_box.pack()

    # Create a Scrollbar widget in the new window
    scrollbar = tk.Scrollbar(history_window, command=history_box.yview)
    scrollbar.pack(side="right", fill="y")

    # Configure the Text widget to use the Scrollbar
    history_box.configure(yscrollcommand=scrollbar.set)

    # Load the message history from the JSON file
    with open('message_history.json', 'r') as file:
        message_history = json.load(file)

    # Sort the message history by timestamp (oldest to newest)
    sorted_message_history = sorted(message_history.items())

    # Display the sorted message history in the Text widget
    for timestamp, message in sorted_message_history:
        history_box.insert(tk.END, f"{timestamp}: {message}\n")

    # Make the Text widget read-only
    history_box.config(state=tk.DISABLED)


enter_username()

root2 = tk.Tk()
root2.title("Chat Room")
root2.protocol("WM_DELETE_WINDOW", on_closing)

chat_box = tk.Text(root2, width=50, height=20)
chat_box.pack()

scrollbar = tk.Scrollbar(root2, command=chat_box.yview)
scrollbar.pack(side="right", fill="y")

chat_box.configure(yscrollcommand=scrollbar.set)

message_box = tk.Entry(root2, width=40)
message_box.pack()

send_button = tk.Button(root2, text="Send", command=client_send)
send_button.pack()

history_button = tk.Button(root2, text="View Message History", command=view_message_history)
history_button.pack()


root2.bind('<Return>', client_send)



receive_thread = threading.Thread(target=client_receive)
receive_thread.start()



send_thread = threading.Thread(target=send_thread_func)
send_thread.start()

root2.mainloop()