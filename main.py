# from modules.generate_key_pair import generate_key_pair
# from modules.sign_document import sign_document
# from modules.verify_signature import verify_signature
# from modules.encrypt_for_recipient import encrypt_for_recipient
# from modules.multi_sign_document import multi_sign_document
# from modules.encrypt_for_recipient import decrypt_document

# def main():
#     """Demo of the complete workflow"""
    
#     # 1. Setup users
#     print("=== User Registration ===")
#     generate_key_pair("sara", "sara_password")
#     generate_key_pair("ahmed", "ahmed_password")
    
#     # 2. Sara signs a document
#     print("\n=== Document Signing ===")
#     sign_document("sara", "secret.txt", "sara_private.pem", "sara_password")
    
#     # 3. Sara encrypts for Ahmed
#     print("\n=== Document Encryption ===")
#     encrypt_for_recipient("sara", "secret.txt", "ahmed")
    
#     # 4. Ahmed decrypts and verifies
#     print("\n=== Document Decryption & Verification ===")
#     decrypted_file = decrypt_document("ahmed", "secret.txt.encrypted", "ahmed_private.pem", "ahmed_password")
#     verify_signature(decrypted_file, "secret.txt.sig")
    
#     # 5. Multi-signature demo
#     print("\n=== Multi-Signature Workflow ===")
#     generate_key_pair("manager1", "manager1_pass")
#     generate_key_pair("manager2", "manager2_pass")
    
#     multi_sign_document(
#         ["sara", "manager1", "manager2"],
#         "budget_secret.txt",
#         ["sara_private.pem", "manager1_private.pem", "manager2_private.pem"],
#         ["sara_password", "manager1_pass", "manager2_pass"]
#     )

# if __name__ == "__main__":
#     main()


import os
import sys
from pathlib import Path
# from integration.DigitalSigningGUI import DigitalSigningGUI
import tkinter as tk


def run_gui():
    """Run the Digital Signing System GUI"""
    
    # Add the integration directory to Python path
    current_dir = Path(__file__).parent
    integration_dir = current_dir / "integration"
    
    if integration_dir.exists():
        sys.path.insert(0, str(integration_dir))
    else:
        print("❌ Error: integration directory not found!")
        return
    
    try:

        DigitalSigningGUI = __import__("DigitalSigningGUI").DigitalSigningGUI        
        print("🚀 Starting Digital Document Signing System GUI...")
        print("Please wait while the interface loads...")
        
        # Create and run the GUI
        root = tk.Tk()
        app = DigitalSigningGUI(root)
        root.mainloop()
        
    except ImportError as e:
        print(f"❌ Error importing GUI: {e}")
        print("Make sure all required files are in the correct locations.")
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")

def run_demo():
    """Run the command-line demo (original functionality)"""
    from modules.generate_key_pair import generate_key_pair
    from modules.sign_document import sign_document
    from modules.verify_signature import verify_signature
    from modules.encrypt_for_recipient import encrypt_for_recipient, decrypt_document
    from modules.multi_sign_document import multi_sign_document

    print("=== Command Line Demo ===")
    
    # 1. Setup users
    print("=== User Registration ===")
    generate_key_pair("sara", "sara_password")
    generate_key_pair("ahmed", "ahmed_password")
    
    # 2. Sara signs a document
    print("\n=== Document Signing ===")
    sign_document("sara", "secret.txt", "sara_private.pem", "sara_password")
    
    # 3. Sara encrypts for Ahmed
    print("\n=== Document Encryption ===")
    encrypt_for_recipient("sara", "secret.txt", "ahmed")
    
    # 4. Ahmed decrypts and verifies
    print("\n=== Document Decryption & Verification ===")
    decrypted_file = decrypt_document("ahmed", "secret.txt.encrypted", "ahmed_private.pem", "ahmed_password")
    verify_signature(decrypted_file, "secret.txt.sig")
    
    # 5. Multi-signature demo
    print("\n=== Multi-Signature Workflow ===")
    generate_key_pair("manager1", "manager1_pass")
    generate_key_pair("manager2", "manager2_pass")
    
    multi_sign_document(
        ["sara", "manager1", "manager2"],
        "budget_secret.txt",
        ["sara_private.pem", "manager1_private.pem", "manager2_private.pem"],
        ["sara_password", "manager1_pass", "manager2_pass"]
    )

def main():
    """Main entry point with menu"""
    print("=" * 50)
    print("    DIGITAL DOCUMENT SIGNING SYSTEM")
    print("=" * 50)
    print("\nChoose an option:")
    print("1. 🖥️  Launch GUI (Recommended)")
    print("2. 💻  Run Command Line Demo")
    print("3. 🚪  Exit")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            run_gui()
            break
        elif choice == "2":
            run_demo()
            break
        elif choice == "3":
            print("Goodbye! 👋")
            break
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()