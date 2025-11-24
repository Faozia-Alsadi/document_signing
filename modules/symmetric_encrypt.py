from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import secrets
import json

SHARED_AES_KEY = secrets.token_bytes(32)  # 256-bit key stored in system

def symmetric_encrypt(document_path, output_path=None):
    """Encrypt document using shared AES key only"""
    
    if output_path is None:
        output_path = f"{document_path}.encrypted"
    
    # Generate random IV
    iv = secrets.token_bytes(16)

    # Read and pad document
    with open(document_path, "rb") as file:
        document_data = file.read()
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(document_data) + padder.finalize()
    
    # Encrypt with AES
    cipher = Cipher(algorithms.AES(SHARED_AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Create encrypted package
    encrypted_package = {
        "encryption_type": "symmetric_only",
        "iv": iv.hex(),
        "encrypted_data": encrypted_data.hex()
    }
    
    # Save encrypted file
    with open(output_path, "w") as f:
        json.dump(encrypted_package, f, indent=2)
    
    print(f"Document symmetrically encrypted! Saved to {output_path}")
    return output_path

def symmetric_decrypt(encrypted_file_path, output_path=None):
    """Decrypt document using shared AES key only"""
    
    if output_path is None:
        output_path = encrypted_file_path.replace(".encrypted", ".decrypted")
    
    # Load encrypted package
    with open(encrypted_file_path, "r") as f:
        encrypted_package = json.load(f)
    
    # Verify it's symmetric encryption
    if encrypted_package.get("encryption_type") != "symmetric_only":
        raise ValueError("This is not a symmetric-only encrypted file")
    
    # Get IV and encrypted data
    iv = bytes.fromhex(encrypted_package["iv"])
    encrypted_data = bytes.fromhex(encrypted_package["encrypted_data"])
    
    # Decrypt
    cipher = Cipher(algorithms.AES(SHARED_AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Save decrypted document
    with open(output_path, "wb") as f:
        f.write(original_data)
    
    print(f"Document symmetrically decrypted! Saved to {output_path}")
    return output_path