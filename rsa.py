from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

backend = default_backend()


# generate a key of 32-byte(128-bit) size
def generate_aes_key():
    return os.urandom(32)


#  generates a pair of RSA private and public keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# takes a public key object and converts it into a byte string using the PEM format.
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


# takes a byte string representing a public key in PEM format and converts it back into a public key object.
def deserialize_public_key(pem):
    public_key = serialization.load_pem_public_key(pem, backend=default_backend())
    return public_key


# encrypt the AES key using RSA public key.
def encrypt_aes_key(public_key, original_aes_key):
    encrypted_key = public_key.encrypt(
        original_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return encrypted_key


# decrypt the AES key using RSA private key.
def decrypt_aes_key(private_key, encrypted_aes_key):
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_key


# encrypts a message with AES-GCM and includes a message hash for integrity.
def encrypt_message(message, aes_key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(message.encode())
    message_hash = hasher.finalize()
    encrypted_data = nonce + ciphertext + encryptor.tag + message_hash
    return encrypted_data


# decrypts an encrypted message, verifies integrity, and returns the plaintext if integrity check passes.
def decrypt_message(encrypted_message, aes_key):
    nonce, ciphertext, tag, decrypted_hash = (encrypted_message[:16], encrypted_message[16:-48],
                                              encrypted_message[-48:-32], encrypted_message[-32:]
                                              )
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(plaintext)
    hashed_plaintext = hasher.finalize()
    if hashed_plaintext == decrypted_hash:
        return plaintext
    else:
        return False
