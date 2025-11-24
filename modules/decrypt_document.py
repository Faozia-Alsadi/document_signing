from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import json

def decrypt_document(recipient_id, encrypted_file_path, private_key_path, password=None):
    """Decrypt document using recipient's private key"""
    
    # Load private key and verify it's RSA
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    
    # Verify it's an RSA key
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA for decryption")
    
    # Load encrypted package
    with open(encrypted_file_path, "r") as f:
        encrypted_package = json.load(f)
    
    # Verify this package is intended for this recipient
    if encrypted_package.get("recipient") != recipient_id:
        print(f"Warning: This document was encrypted for {encrypted_package.get('recipient')}, not {recipient_id}")
    
    # Decrypt AES key
    encrypted_aes_key = bytes.fromhex(encrypted_package["encrypted_aes_key"])
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt document
    iv = bytes.fromhex(encrypted_package["iv"])
    encrypted_data = bytes.fromhex(encrypted_package["encrypted_data"])
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Save decrypted document
    decrypted_file = encrypted_file_path.replace(".encrypted", ".decrypted")
    with open(decrypted_file, "wb") as f:
        f.write(original_data)
    
    print(f"Document decrypted! Saved to {decrypted_file}")
    return decrypted_file