from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json

def verify_signature(document_path, signature_file_path):
    """Verify a document's digital signature"""
    
    # Load signature package
    with open(signature_file_path, "r") as f:
        signature_package = json.load(f)
    
    # Load signer's public key - ensure it's RSA
    signer_id = signature_package["signer"]
    with open(f"key_directory/{signer_id}_public.pem", "rb") as key_file:
        signer_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    # Verify it's an RSA key
    if not isinstance(signer_public_key, rsa.RSAPublicKey):
        raise TypeError("The public key must be an RSA key")
    
    # Read document
    with open(document_path, "rb") as file:
        document_data = file.read()
    
    # Compute hash
    document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    document_hash.update(document_data)
    digest = document_hash.finalize()
    
    # Verify signature
    signature = bytes.fromhex(signature_package["signature"])
    
    try:
        signer_public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✓ Signature is VALID! Document is authentic and untampered.")
        print(f"  Signed by: {signer_id}")
        print(f"  Timestamp: {signature_package['timestamp']}")
        return True
    except Exception as e:
        print(f"✗ Signature is INVALID! {str(e)}")
        return False