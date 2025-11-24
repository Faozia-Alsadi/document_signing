from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def generate_key_pair(user_id, password=None):
    """Generate RSA key pair for a user"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Save private key (optionally encrypted with password)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )
    
    with open(f"{user_id}_private.pem", "wb") as f:
        f.write(private_pem)
    
    # Save public key to system directory
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    os.makedirs("key_directory", exist_ok=True)
    with open(f"key_directory/{user_id}_public.pem", "wb") as f:
        f.write(public_pem)
    
    print(f"Key pair generated for {user_id}")
    return private_key, public_key
