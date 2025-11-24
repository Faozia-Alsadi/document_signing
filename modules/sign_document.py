import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def sign_document(user_id, document_path, private_key_path, password=None):
    
    # Load private key and ensure it's RSA
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    
    # Verify it's an RSA key
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The private key must be an RSA key. Please generate RSA keys using generate_key_pair()")
    
    # Read document
    with open(document_path, "rb") as file:
        document_data = file.read()
    
    # Compute hash
    document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    document_hash.update(document_data)
    digest = document_hash.finalize()
    
    # Sign the hash
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()  # Hash algorithm
    )
    
    # Create signature package
    signature_package = {
        "document": document_path,
        "signer": user_id,
        "timestamp": datetime.now().isoformat(),
        "signature": signature.hex(),
        "hash_algorithm": "SHA256"
    }
    
    # Save signature
    signature_file = f"{document_path}.sig"
    with open(signature_file, "w") as f:
        json.dump(signature_package, f, indent=2)
    
    print(f"Document signed successfully! Signature saved to {signature_file}")
    return signature_file
