import json
import os
from modules.sign_document import sign_document
from modules.verify_signature import verify_signature

def multi_sign_document(signers, document_path, private_key_paths, passwords=None):
    """Multiple users sign the same document"""
    
    if passwords is None:
        passwords = [None] * len(signers)
    
    all_signatures = []
    
    for i, (signer_id, private_key_path, password) in enumerate(zip(signers, private_key_paths, passwords)):
        print(f"\n--- Signer {i+1}: {signer_id} ---")
        print(f"Using private key: {private_key_path}")
        
        # Check if private key file exists
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
        
        # Each signer signs the document
        signature_file = sign_document(signer_id, document_path, private_key_path, password)
        
        # Read the signature data from the file
        with open(signature_file, "r") as f:
            signature_data = json.load(f)
        
        all_signatures.append(signature_data)
        
        # Create a combined signature package
        multi_sig_package = {
            "document": document_path,
            "signature_chain": all_signatures,
            "total_signers": len(signers),
            "completed_signers": i + 1,
            "version": "1.0"
        }
        
        # Save intermediate state
        multi_sig_file = f"{document_path}.multisig"
        with open(multi_sig_file, "w") as f:
            json.dump(multi_sig_package, f, indent=2)
    
    print(f"\n✓ Multi-signature completed! All {len(signers)} signatures collected.")
    print(f"Multi-signature file: {multi_sig_file}")
    return multi_sig_file

def verify_multi_signature(document_path, multi_sig_file_path):
    """Verify all signatures in a multi-signature document"""
    
    try:
        # Check if multi-signature file exists
        if not os.path.exists(multi_sig_file_path):
            raise FileNotFoundError(f"Multi-signature file not found: {multi_sig_file_path}")
        
        # Load and validate multi-signature package
        with open(multi_sig_file_path, "r") as f:
            multi_sig_package = json.load(f)
        
        # Validate the package structure
        if not isinstance(multi_sig_package, dict):
            raise ValueError("Multi-signature file is not a valid JSON object")
        
        if 'signature_chain' not in multi_sig_package:
            raise KeyError("Multi-signature file missing 'signature_chain' field")
        
        if not isinstance(multi_sig_package['signature_chain'], list):
            raise ValueError("'signature_chain' should be a list of signatures")
        
        signature_chain = multi_sig_package['signature_chain']
        
        if len(signature_chain) == 0:
            raise ValueError("No signatures found in signature chain")
        
        print(f"Verifying {len(signature_chain)} signatures...")
        
        all_valid = True
        
        for i, signature_data in enumerate(signature_chain):
            # Validate signature data structure
            if 'signer' not in signature_data:
                print(f"✗ Signature {i+1} missing 'signer' field")
                all_valid = False
                continue
            
            signer_id = signature_data['signer']
            print(f"\n--- Verifying signature {i+1} from {signer_id} ---")
            
            try:
                # Create a temporary signature file for verification
                temp_sig_file = f"temp_sig_{i}_{os.getpid()}.sig"  # Use PID to avoid conflicts
                with open(temp_sig_file, "w") as f:
                    json.dump(signature_data, f, indent=2)
                
                # Verify each signature
                is_valid = verify_signature(document_path, temp_sig_file)
                
                # Clean up temporary file
                os.remove(temp_sig_file)
                
                if not is_valid:
                    all_valid = False
                    print(f"✗ Signature from {signer_id} is INVALID!")
                else:
                    print(f"✓ Signature from {signer_id} is VALID!")
                    
            except Exception as e:
                print(f"✗ Error verifying signature from {signer_id}: {e}")
                all_valid = False
        
        # Print comprehensive results
        print(f"\n" + "="*50)
        if all_valid:
            print(f"✅ ALL {len(signature_chain)} signatures are VALID!")
            print(f"📄 Document '{os.path.basename(document_path)}' approved by all parties.")
        else:
            print(f"❌ SOME SIGNATURES ARE INVALID!")
            print(f"📄 Document '{os.path.basename(document_path)}' verification failed.")
        print("="*50)
        
        return all_valid
        
    except Exception as e:
        print(f"❌ Multi-signature verification failed: {e}")
        return False

def get_multi_signature_info(multi_sig_file_path):
    """Get information about a multi-signature file"""
    try:
        if not os.path.exists(multi_sig_file_path):
            return {"error": "File not found"}
        
        with open(multi_sig_file_path, "r") as f:
            multi_sig_package = json.load(f)
        
        info = {
            "document": multi_sig_package.get('document', 'Unknown'),
            "total_signers": multi_sig_package.get('total_signers', 0),
            "completed_signers": multi_sig_package.get('completed_signers', 0),
            "signatures": []
        }
        
        if 'signature_chain' in multi_sig_package:
            for sig in multi_sig_package['signature_chain']:
                info['signatures'].append({
                    'signer': sig.get('signer', 'Unknown'),
                    'timestamp': sig.get('timestamp', 'Unknown')
                })
        
        return info
        
    except Exception as e:
        return {"error": str(e)}