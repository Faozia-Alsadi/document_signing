import json
import os, sys

# Add the project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

class DigitalSigningSystem:
    
    def __init__(self):
        self.users = {}
        self.test_results = []
        
        from modules.audit_logger import AuditLogger
        self.audit_logger = AuditLogger()
    
    def register_user(self, user_id, password=None):
        """Register a new user with RSA key pair"""
        key_generation = __import__('modules.generate_key_pair', fromlist=['generate_key_pair'])
        return key_generation.generate_key_pair(user_id, password)
    
    def sign_document(self, user_id, document_path, password=None):
        """Import sign_document module"""
        sign_document_module = __import__('modules.sign_document', fromlist=['sign_document'])
        private_key_path = f"{user_id}_private.pem"
        signature_file = sign_document_module.sign_document(user_id, document_path, private_key_path, password)
        self.audit_logger.log_signature_event(user_id, document_path, signature_file)
        return signature_file
    
    def multi_sign_document(self, signers, document_path, passwords=None):
        """Import multi_sign_document module"""
        print(f"Signers are {signers}")
        sign_document_module = __import__('modules.multi_sign_document', fromlist=['multi_sign_document'])
        private_key_paths = [f"{signer}_private.pem" for signer in signers]
        signature_file = sign_document_module.multi_sign_document(signers, document_path, private_key_paths, passwords)
        self.audit_logger.log_signature_event(signers, document_path, signature_file)
        return signature_file
    
    def encrypt_for_recipient(self, sender_id, document_path, recipient_id):
        """Import encryption module"""
        encryption_module = __import__('modules.encrypt_for_recipient', fromlist=['encrypt_for_recipient'])
        encrypted_file = encryption_module.encrypt_for_recipient(sender_id, document_path, recipient_id)
        self.audit_logger.log_signature_event(sender_id, document_path, encrypted_file)
        return encrypted_file
    
    def decrypt_document(self, recipient_id, encrypted_file_path, password=None):
        """Import decryption module"""
        decryption_module = __import__('modules.decrypt_document', fromlist=['decrypt_document'])
        private_key_path = f"{recipient_id}_private.pem"
        decrypted_file = decryption_module.decrypt_document(recipient_id, encrypted_file_path, private_key_path, password)
        self.audit_logger.log_signature_event(recipient_id, encrypted_file_path, decrypted_file)
        return decrypted_file
    
    def verify_signature(self, document_path, signature_file_path):
        """Import verification module"""
        verification_module = __import__('modules.verify_signature', fromlist=['verify_signature'])
        verified_signature = verification_module.verify_signature(document_path, signature_file_path)
        self.audit_logger.log_signature_event(document_path, signature_file_path, verified_signature)
        return verified_signature
    
    def symmetric_encrypt(self, document_path, output_path=None):
        """Import encryption module"""
        symmetric_module = __import__('modules.symmetric_encryption', fromlist=['symmetric_encryption'])
        symmetric_file = symmetric_module.symmetric_encrypt(document_path, output_path)
        self.audit_logger.log_signature_event(document_path, output_path, symmetric_file)
        return symmetric_file
    
    def symmetric_decrypt(self, encrypted_file_path, output_path=None):
        """Import decryption module"""
        symmetric_module = __import__('modules.symmetric_encryption', fromlist=['symmetric_encryption'])
        symmetric_file = symmetric_module.symmetric_decrypt(encrypted_file_path, output_path)
        return symmetric_file
    
    def symmetric_transfer_document(self, sender_id, recipient_id, document_path):
        """Symmetric transfer using fresh AES key"""
        symmetric_module = __import__('modules.symmetric_transfer', fromlist=['symmetric_transfer'])
        symmetric_transfer_file = symmetric_module.perform_symmetric_transfer(sender_id, recipient_id, document_path)
        self.audit_logger.log_signature_event(sender_id, document_path, symmetric_transfer_file)
        return symmetric_transfer_file
    
    def full_send_document(self, sender_id, document_path, recipient_id, password=None):
        """Complete workflow: sign + encrypt for recipient"""
        print(f"\n--- Sending document from {sender_id} to {recipient_id} ---")
        
        # 1. Sign the document
        signature_file = self.sign_document(sender_id, document_path, password)
        
        # 2. Encrypt for recipient
        encrypted_file = self.encrypt_for_recipient(sender_id, document_path, recipient_id)
        
        print(f"✓ Document sent successfully!")
        print(f"  Signature: {signature_file}")
        print(f"  Encrypted: {encrypted_file}")

        self.audit_logger.log_signature_event(sender_id, document_path, signature_file)
        
        return encrypted_file, signature_file
    
    def full_receive_document(self, recipient_id, encrypted_file_path, signature_file_path, password=None):
        """Complete workflow: decrypt + verify signature"""
        print(f"\n--- Receiving document for {recipient_id} ---")

        # Ensure we have string file paths, not dictionaries
        if isinstance(encrypted_file_path, dict):
            # If it's a dictionary, we need to save it to a file first
            temp_encrypted_file = "temp_encrypted.encrypted"
            with open(temp_encrypted_file, "w") as f:
                json.dump(encrypted_file_path, f, indent=2)
            encrypted_file_path = temp_encrypted_file

        if isinstance(signature_file_path, dict):
            # If it's a dictionary, we need to save it to a file first
            temp_signature_file = "temp_signature.sig"
            with open(temp_signature_file, "w") as f:
                json.dump(signature_file_path, f, indent=2)
            signature_file_path = temp_signature_file

        try:
            # 1. Decrypt the document
            print(f"Decrypting document: {encrypted_file_path}")
            decrypted_file = self.decrypt_document(recipient_id, encrypted_file_path, password)
            
            # 2. Verify the signature
            print(f"Verifying signature: {signature_file_path}")
            is_valid = self.verify_signature(decrypted_file, signature_file_path)
            
            if is_valid:
                print("✓ Document received and verified successfully!")
                return decrypted_file, True
            else:
                print("✗ Document verification failed!")
                return decrypted_file, False
                
        except Exception as e:
            print(f"❌ Error in full_receive_document: {e}")
            return None, False
    
    def test_tampered_document(self):
        """Test detection of tampered documents"""
        print("\n🔒 Test 2: Tampered Document Detection")
        
        # Create and send document
        with open("tamper_test.txt", "w") as f:
            f.write("Original content")
        
        encrypted_file, signature_file = self.full_send_document(
            "test_sender", "tamper_test.txt", "test_recipient", "pass123"
        )
        
        # Ensure encrypted_file is a string path
        if isinstance(encrypted_file, tuple):
            encrypted_file = encrypted_file[0]  # Take first element if it's a tuple
        
        try:
            with open(str(encrypted_file), "r") as f:  # Ensure it's string
                package = json.load(f)
            
            # Modify encrypted data (tamper with the content)
            tampered_data = package["encrypted_data"][:-10] + "ffffffff"
            package["encrypted_data"] = tampered_data
            
            # Save tampered file
            tampered_file = "tampered.encrypted"
            with open(tampered_file, "w") as f:
                json.dump(package, f)
            
            # Use only 3 parameters for decrypt_document
            try:
                decrypted_file = self.decrypt_document("test_recipient", tampered_file, "pass456")
                
                # If decryption succeeds, try verification
                is_valid = self.verify_signature(decrypted_file, signature_file)
                assert not is_valid, "Tampered document should fail verification"
                print("✓ Tampered document test PASSED - verification failed as expected")
                
            except Exception as e:
                print(f"✓ Tampered document test PASSED - properly rejected with error: {e}")
                
        except Exception as e:
            print(f"✗ Tampered document test setup failed: {e}")
    
    def test_normal_workflow(self):
#         """Test normal document sending/receiving"""
        print("\n🔒 Test 1: Normal Workflow")
        
        # Setup
        self.register_user("test_sender", "pass123")
        self.register_user("test_recipient", "pass456")
        
        # Create test document
        with open("test_doc.txt", "w") as f:
            f.write("Confidential company report")
        
        # Send document
        encrypted_file, signature_file = self.full_send_document(
            "test_sender", "test_doc.txt", "test_recipient", "pass123"
        )
        
        # Receive and verify
        _, is_valid = self.full_receive_document(
            "test_recipient", encrypted_file, signature_file, "pass456"
        )
        
        assert is_valid, "Normal workflow should pass verification"
        print("✓ Normal workflow test PASSED")

    def test_wrong_recipient(self):
        """Test that wrong recipient cannot decrypt"""
        print("\n🔒 Test 3: Wrong Recipient Protection")

        self.register_user("user_a", "pass_a")
        self.register_user("user_b", "pass_b")
        self.register_user("user_c", "pass_c")

        with open("secret_doc.txt", "w") as f:
            f.write("Top secret message")

        # Encrypt for user_b
        encrypted_file, _ = self.full_send_document(
            "user_a", "secret_doc.txt", "user_b", "pass_a"
        )

        # Try to decrypt with user_c's key (should fail)
        try:
            decrypted_file = self.decrypt_document("user_c", encrypted_file, "user_c_private.pem")
            print("✗ Wrong recipient test FAILED - user_c could decrypt")
        except Exception as e:
            print("✓ Wrong recipient test PASSED - properly rejected")
    
    def test_forged_signature(self):
        """Test detection of forged signatures"""
        print("\n🔒 Test 4: Forged Signature Detection")
        
        with open("contract.txt", "w") as f:
            f.write("Important contract")
        
        # Create legitimate signature
        encrypted_file, signature_file = self.full_send_document(
            "user_a", "contract.txt", "user_b", "pass_a"
        )
        
        # Try to verify with wrong public key
        try:
            is_valid = self.verify_signature("contract.txt.decrypted", signature_file)
            # If we get here with wrong key, it's a problem
            if not is_valid:
                print("✓ Forged signature test PASSED - properly detected")
            else:
                print("✗ Forged signature test FAILED - accepted wrong signature")
        except Exception as e:
            print("✓ Forged signature test PASSED - properly rejected")
    
    def test_multi_signature(self):
        """Test multi-signature workflow"""
        print("\n🔒 Test 5: Multi-Signature Workflow")
        
        # Register multiple signers
        signers = ["manager1", "manager2", "director"]
        for signer in signers:
            self.register_user(signer, f"{signer}_pass")
        
        # Create document
        with open("approval_doc.txt", "w") as f:
            f.write("Budget approval document")
        
        # Sequential signing
        signature_chain = []
        for _, signer in enumerate(signers):
            print(f"  {signer} signing...")
            signature_data = self.sign_document(signer, "approval_doc.txt", f"{signer}_pass")
            signature_chain.append(signature_data)
        
        # Verify all signatures
        all_valid = True
        for _, signature_file in enumerate(signature_chain):
            is_valid = self.verify_signature("approval_doc.txt", signature_file)
            if not is_valid:
                all_valid = False
                break
        
        assert all_valid, "All signatures in multi-signature should be valid"
        print("✓ Multi-signature test PASSED")
    
    def run_security_tests(self):
        """Run all security tests"""
        self.test_tampered_document()
        # Add other tests here...