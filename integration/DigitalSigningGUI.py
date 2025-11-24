import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import os
import threading
from DigitalSigningSystem import DigitalSigningSystem
from pathlib import Path

class DigitalSigningGUI:
    """Phase 6: Complete GUI implementation"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Document Signing System")
        self.root.geometry("700x500")
        
        # Initialize the backend system
        self.system = DigitalSigningSystem()
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the main GUI interface"""
        
        # Main notebook for different functionalities
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # User Registration Tab
        reg_frame = ttk.Frame(notebook)
        notebook.add(reg_frame, text="User Registration")
        self.setup_registration_tab(reg_frame)
        
        # Document Signing Tab
        sign_frame = ttk.Frame(notebook)
        notebook.add(sign_frame, text="Sign Document")
        self.setup_signing_tab(sign_frame)
        
        # Multi-Document Signing Tab
        sign_frame = ttk.Frame(notebook)
        notebook.add(sign_frame, text="Multi-Signed Document")
        self.setup_multi_signing_tab(sign_frame)
        
        # NEW: Multi-Verification Tab
        multi_verify_frame = ttk.Frame(notebook)
        notebook.add(multi_verify_frame, text="Multi-Verify")
        self.setup_multi_verification_tab(multi_verify_frame)
        
        # Encryption Tab
        enc_frame = ttk.Frame(notebook)
        notebook.add(enc_frame, text="Encrypt Document")
        self.setup_encryption_tab(enc_frame)
        
        # Verification Tab
        verify_frame = ttk.Frame(notebook)
        notebook.add(verify_frame, text="Verify Signature")
        self.setup_verification_tab(verify_frame)
        
        # Symmetric Transfer Tab
        verify_frame = ttk.Frame(notebook)
        notebook.add(verify_frame, text="Symmetric Transfer")
        self.setup_symmetric_transfer_tab(verify_frame)
        
        # NEW: Symmetric Verification Tab
        sym_verify_frame = ttk.Frame(notebook)
        notebook.add(sym_verify_frame, text="Symmetric Verify")
        self.setup_symmetric_verification_tab(sym_verify_frame)
        
        # Testing Tab
        test_frame = ttk.Frame(notebook)
        notebook.add(test_frame, text="Run Tests")
        self.setup_testing_tab(test_frame)
    
    def setup_registration_tab(self, parent):
        """Setup user registration interface"""
        # Title
        ttk.Label(parent, text="User Registration", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # User ID
        ttk.Label(parent, text="User ID:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.user_id_entry = ttk.Entry(parent, width=25)
        self.user_id_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Password
        ttk.Label(parent, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.password_entry = ttk.Entry(parent, width=25, show='*')
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Register Button
        ttk.Button(parent, text="Register User", 
                  command=self.register_user_gui).grid(row=3, column=0, columnspan=2, pady=15)
        
        # Status display
        self.reg_status = ttk.Label(parent, text="", foreground="green")
        self.reg_status.grid(row=4, column=0, columnspan=2, pady=5)
    
    def setup_signing_tab(self, parent):
        """Setup document signing interface"""
        # Title
        ttk.Label(parent, text="Document Signing", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Document selection
        ttk.Label(parent, text="Select Document:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.sign_file_entry = ttk.Entry(parent, width=30)
        self.sign_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                  command=lambda: self.browse_file(self.sign_file_entry)).grid(row=1, column=2, padx=5)
        
        # Signer information
        ttk.Label(parent, text="Signer ID:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.signer_id_entry = ttk.Entry(parent, width=25)
        self.signer_id_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(parent, text="Password:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.signer_password_entry = ttk.Entry(parent, width=25, show='*')
        self.signer_password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Sign Button
        ttk.Button(parent, text="Sign Document", 
                  command=self.sign_document_gui).grid(row=4, column=0, columnspan=3, pady=15)
        
        # Status display
        self.sign_status = ttk.Label(parent, text="", foreground="green")
        self.sign_status.grid(row=5, column=0, columnspan=3, pady=5)
    
    def setup_multi_signing_tab(self, parent):
        """Setup multi-document signing interface"""
        # Title
        ttk.Label(parent, text="Multi-Signature Document", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Document selection
        ttk.Label(parent, text="Select Document:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.multi_sign_file_entry = ttk.Entry(parent, width=30)
        self.multi_sign_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                command=lambda: self.browse_file(self.multi_sign_file_entry)).grid(row=1, column=2, padx=5)
        
        # Signers information
        ttk.Label(parent, text="Signer IDs (comma-separated):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.multi_signer_ids_entry = ttk.Entry(parent, width=25)
        self.multi_signer_ids_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Passwords information
        ttk.Label(parent, text="Passwords (comma-separated):").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.multi_signer_passwords_entry = ttk.Entry(parent, width=25, show='*')
        self.multi_signer_passwords_entry.grid(row=3, column=1, padx=5, pady=5)
        ttk.Label(parent, text="Leave empty if no passwords", font=('Arial', 8)).grid(row=4, column=1, sticky='w')
        
        # Sign Button
        ttk.Button(parent, text="Sign Document with Multiple Signers", 
                command=self.multi_sign_document_gui).grid(row=5, column=0, columnspan=3, pady=15)
        
        # Status display
        self.multi_sign_status = ttk.Label(parent, text="", foreground="green")
        self.multi_sign_status.grid(row=6, column=0, columnspan=3, pady=5)

    def setup_encryption_tab(self, parent):
        """Setup document encryption interface"""
        # Title
        ttk.Label(parent, text="Document Encryption", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Document selection
        ttk.Label(parent, text="Select Document:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.enc_file_entry = ttk.Entry(parent, width=30)
        self.enc_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                  command=lambda: self.browse_file(self.enc_file_entry)).grid(row=1, column=2, padx=5)
        
        # Recipient information
        ttk.Label(parent, text="Sender ID:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.sender_id_entry = ttk.Entry(parent, width=25)
        self.sender_id_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(parent, text="Recipient ID:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.recipient_id_entry = ttk.Entry(parent, width=25)
        self.recipient_id_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Encrypt Button
        ttk.Button(parent, text="Encrypt Document", 
                  command=self.encrypt_document_gui).grid(row=4, column=0, columnspan=3, pady=15)
        
        # Status display
        self.enc_status = ttk.Label(parent, text="", foreground="green")
        self.enc_status.grid(row=5, column=0, columnspan=3, pady=5)
    
    def setup_verification_tab(self, parent):
        """Setup signature verification interface"""
        # Title
        ttk.Label(parent, text="Signature Verification", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Document selection
        ttk.Label(parent, text="Select Document:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.verify_file_entry = ttk.Entry(parent, width=30)
        self.verify_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                  command=lambda: self.browse_file(self.verify_file_entry)).grid(row=1, column=2, padx=5)
        
        # Signature file selection
        ttk.Label(parent, text="Signature File:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.sig_file_entry = ttk.Entry(parent, width=30)
        self.sig_file_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                  command=lambda: self.browse_file(self.sig_file_entry)).grid(row=2, column=2, padx=5)
        
        # Verify Button
        ttk.Button(parent, text="Verify Signature", 
                  command=self.verify_signature_gui).grid(row=3, column=0, columnspan=3, pady=15)
        
        # Status display
        self.verify_status = ttk.Label(parent, text="", foreground="green")
        self.verify_status.grid(row=4, column=0, columnspan=3, pady=5)
        
        # Result display
        self.verify_result = ttk.Label(parent, text="", font=('Arial', 10, 'bold'))
        self.verify_result.grid(row=5, column=0, columnspan=3, pady=5)
    
    def setup_multi_verification_tab(self, parent):
        """Setup multi-signature verification interface"""
        # Title
        ttk.Label(parent, text="Multi-Signature Verification", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Document selection
        ttk.Label(parent, text="Select Document:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.multi_verify_file_entry = ttk.Entry(parent, width=30)
        self.multi_verify_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                command=lambda: self.browse_file(self.multi_verify_file_entry)).grid(row=1, column=2, padx=5)
        
        # Multi-signature file selection
        ttk.Label(parent, text="Multi-Signature File:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.multi_sig_file_entry = ttk.Entry(parent, width=30)
        self.multi_sig_file_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                command=lambda: self.browse_file(self.multi_sig_file_entry)).grid(row=2, column=2, padx=5)
        
        # Verify Button
        ttk.Button(parent, text="Verify Multi-Signature", 
                command=self.verify_multi_signature_gui).grid(row=3, column=0, columnspan=3, pady=15)
        
        # Status display
        self.multi_verify_status = ttk.Label(parent, text="", foreground="green")
        self.multi_verify_status.grid(row=4, column=0, columnspan=3, pady=5)
        
        # Result display
        self.multi_verify_result = ttk.Label(parent, text="", font=('Arial', 10, 'bold'))
        self.multi_verify_result.grid(row=5, column=0, columnspan=3, pady=5)

    def setup_symmetric_transfer_tab(self, parent):
        """Setup symmetric transfer interface"""
        # Title
        ttk.Label(parent, text="Symmetric Transfer", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Document selection
        ttk.Label(parent, text="Select Document:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.symmetric_file_entry = ttk.Entry(parent, width=30)
        self.symmetric_file_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", 
                command=lambda: self.browse_file(self.symmetric_file_entry)).grid(row=1, column=2, padx=5)
        
        # Parties information
        ttk.Label(parent, text="Sender ID:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.symmetric_sender_entry = ttk.Entry(parent, width=25)
        self.symmetric_sender_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(parent, text="Recipient ID:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.symmetric_recipient_entry = ttk.Entry(parent, width=25)
        self.symmetric_recipient_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Transfer Button
        ttk.Button(parent, text="Perform Symmetric Transfer", 
                command=self.symmetric_transfer_gui).grid(row=4, column=0, columnspan=3, pady=15)
        
        # Key display
        ttk.Label(parent, text="Shared Key:").grid(row=5, column=0, padx=5, pady=5, sticky='w')
        self.shared_key_display = ttk.Entry(parent, width=40, state='readonly')
        self.shared_key_display.grid(row=5, column=1, columnspan=2, padx=5, pady=5)
        
        # Status display
        self.symmetric_status = ttk.Label(parent, text="", foreground="green")
        self.symmetric_status.grid(row=6, column=0, columnspan=3, pady=5)
    
    def setup_symmetric_verification_tab(self, parent):
        """Setup symmetric transfer verification interface"""
        # Title
        ttk.Label(parent, text="Symmetric Transfer Verification", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Description
        desc_text = "Verify the integrity and authenticity of symmetrically encrypted documents.\nUses HMAC to detect tampering and verify the sender."
        ttk.Label(parent, text=desc_text, justify='left').grid(row=1, column=0, columnspan=3, pady=5, padx=10, sticky='w')
        
        # Encrypted file selection
        ttk.Label(parent, text="Select Encrypted File:").grid(row=2, column=0, padx=10, pady=8, sticky='w')
        self.sym_verify_file_entry = ttk.Entry(parent, width=35)
        self.sym_verify_file_entry.grid(row=2, column=1, padx=5, pady=8)
        ttk.Button(parent, text="Browse", 
                command=lambda: self.browse_file(self.sym_verify_file_entry)).grid(row=2, column=2, padx=5, pady=8)
        
        # Shared key input
        ttk.Label(parent, text="Shared AES Key (hex):").grid(row=3, column=0, padx=10, pady=8, sticky='w')
        self.shared_key_entry = ttk.Entry(parent, width=45)
        self.shared_key_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=8, sticky='we')
        
        # Expected sender (optional)
        ttk.Label(parent, text="Expected Sender (optional):").grid(row=4, column=0, padx=10, pady=8, sticky='w')
        self.expected_sender_entry = ttk.Entry(parent, width=25)
        self.expected_sender_entry.grid(row=4, column=1, padx=5, pady=8, sticky='w')
        
        # Verify Button
        ttk.Button(parent, text="Verify & Decrypt Document", 
                command=self.verify_symmetric_transfer_gui).grid(row=5, column=0, columnspan=3, pady=20)
        
        # Verification result display
        self.sym_verify_result = ttk.Label(parent, text="", font=('Arial', 11, 'bold'), justify='left')
        self.sym_verify_result.grid(row=6, column=0, columnspan=3, pady=10, padx=10, sticky='w')
        
        # Detailed results frame
        results_frame = ttk.LabelFrame(parent, text="Verification Details")
        results_frame.grid(row=7, column=0, columnspan=3, padx=10, pady=5, sticky='we')
        
        # Results labels
        self.sym_sender_label = ttk.Label(results_frame, text="Sender: -")
        self.sym_sender_label.grid(row=0, column=0, padx=10, pady=2, sticky='w')
        
        self.sym_integrity_label = ttk.Label(results_frame, text="Integrity: -")
        self.sym_integrity_label.grid(row=0, column=1, padx=20, pady=2, sticky='w')
        
        self.sym_timestamp_label = ttk.Label(results_frame, text="Timestamp: -")
        self.sym_timestamp_label.grid(row=1, column=0, padx=10, pady=2, sticky='w')
        
        self.sym_filename_label = ttk.Label(results_frame, text="Original File: -")
        self.sym_filename_label.grid(row=1, column=1, padx=20, pady=2, sticky='w')
        
        # Status display
        self.sym_verify_status = ttk.Label(parent, text="", foreground="green")
        self.sym_verify_status.grid(row=8, column=0, columnspan=3, pady=5)

    def clear_symmetric_verification_results(self):
        """Clear all verification result displays"""
        self.sym_verify_result.config(text="")
        self.sym_sender_label.config(text="Sender: -")
        self.sym_integrity_label.config(text="Integrity: -")
        self.sym_timestamp_label.config(text="Timestamp: -")
        self.sym_filename_label.config(text="Original File: -")

    def update_symmetric_verification_results(self, result):
        """Update the verification details display"""
        # Sender info
        sender_text = f"Sender: {result['sender']}"
        if result['sender_valid']:
            sender_text += " ✅"
        else:
            sender_text += " ❌"
        self.sym_sender_label.config(text=sender_text)
        
        # Integrity
        integrity_text = f"Integrity: {'✅ VALID' if result['integrity_valid'] else '❌ TAMPERED'}"
        self.sym_integrity_label.config(text=integrity_text)
        
        # Timestamp
        timestamp = result.get('timestamp', 'Unknown')
        if timestamp != 'Unknown':
            # Format timestamp for better readability
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                timestamp = formatted_time
            except:
                pass
        self.sym_timestamp_label.config(text=f"Timestamp: {timestamp}")
        
        # Original filename
        original_file = result.get('original_filename', 'Unknown')
        self.sym_filename_label.config(text=f"Original File: {original_file}")
    
    
    def symmetric_transfer_gui(self):
        """GUI implementation for symmetric transfer"""
        document_path = self.symmetric_file_entry.get().strip()
        sender_id = self.symmetric_sender_entry.get().strip()
        recipient_id = self.symmetric_recipient_entry.get().strip()
        
        if not all([document_path, sender_id, recipient_id]):
            self.update_status(self.symmetric_status, "Error: Please fill all required fields", True)
            return
        
        if not os.path.exists(document_path):
            self.update_status(self.symmetric_status, "Error: Document file does not exist", True)
            return
        
        try:
            # Show processing
            self.update_status(self.symmetric_status, "Performing symmetric transfer with fresh key...")
            
            # Call backend system
            encrypted_file, decrypted_file, shared_key = self.system.symmetric_transfer_document(
                sender_id, recipient_id, document_path
            )
            
            # Display the shared key
            self.shared_key_display.config(state='normal')
            self.shared_key_display.delete(0, tk.END)
            self.shared_key_display.insert(0, shared_key)
            self.shared_key_display.config(state='readonly')
            
            self.update_status(self.symmetric_status, 
                            f"✅ Symmetric transfer completed!\nEncrypted: {encrypted_file}\nDecrypted: {decrypted_file}")
            
            # Clear input fields
            self.symmetric_file_entry.delete(0, tk.END)
            self.symmetric_sender_entry.delete(0, tk.END)
            self.symmetric_recipient_entry.delete(0, tk.END)
            
        except Exception as e:
            self.update_status(self.symmetric_status, f"Error: {str(e)}", True)

    def verify_multi_signature_gui(self):
        """GUI implementation for multi-signature verification - IMPROVED"""
        document_path = self.multi_verify_file_entry.get().strip()
        multi_sig_path = self.multi_sig_file_entry.get().strip()
        
        if not all([document_path, multi_sig_path]):
            self.update_status(self.multi_verify_status, "Error: Please select both document and multi-signature files", True)
            return
        
        if not os.path.exists(document_path):
            self.update_status(self.multi_verify_status, "Error: Document file does not exist", True)
            return
        
        if not os.path.exists(multi_sig_path):
            self.update_status(self.multi_verify_status, "Error: Multi-signature file does not exist", True)
            return
        
        try:
            # Show processing
            self.update_status(self.multi_verify_status, "Verifying multi-signature...")
            
            # First, check the multi-signature file structure
            multi_sign_module = __import__('modules.multi_sign_document', fromlist=['multi_sign_document'])
            file_info = multi_sign_module.get_multi_signature_info(multi_sig_path)
            
            if 'error' in file_info:
                self.update_status(self.multi_verify_status, f"Error: Invalid multi-signature file - {file_info['error']}", True)
                self.multi_verify_result.config(text="")
                return
            
            # Show file info
            info_text = f"File contains {file_info['completed_signers']}/{file_info['total_signers']} signatures"
            self.update_status(self.multi_verify_status, f"Checking multi-signature... {info_text}")
            
            # Now verify the signatures
            is_valid = multi_sign_module.verify_multi_signature(document_path, multi_sig_path)
            
            if is_valid:
                self.multi_verify_result.config(
                    text=f"✅ ALL SIGNATURES VALID\n{file_info['completed_signers']} signatures verified", 
                    foreground="green"
                )
                self.update_status(self.multi_verify_status, "Multi-signature verification completed successfully!")
            else:
                self.multi_verify_result.config(
                    text=f"❌ SOME SIGNATURES INVALID\nVerification failed", 
                    foreground="red"
                )
                self.update_status(self.multi_verify_status, "Multi-signature verification failed!", True)
                
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.update_status(self.multi_verify_status, error_msg, True)
            self.multi_verify_result.config(text="")

    def setup_testing_tab(self, parent):
        """Setup testing interface"""
        # Title
        ttk.Label(parent, text="Security Testing", font=('Arial', 12, 'bold')).pack(pady=10)

        # Test description
        desc_text = "Run comprehensive security tests to verify all system functionalities including:\n• Normal workflow\n• Tampered document detection\n• Wrong recipient protection\n• Forged signature detection\n• Multi-signature workflow"
        ttk.Label(parent, text=desc_text, justify='left').pack(pady=10)
        
        # Run Tests Button
        ttk.Button(parent, text="Run All Security Tests", 
                  command=self.run_all_tests_gui).pack(pady=20)
        
        # Test output area
        ttk.Label(parent, text="Test Output:").pack(anchor='w', padx=10)
        self.test_output = scrolledtext.ScrolledText(parent, height=15, width=80)
        self.test_output.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Clear button
        ttk.Button(parent, text="Clear Output", 
                  command=self.clear_test_output).pack(pady=5)
    
    def browse_file(self, entry_widget):
        """Open file dialog and update entry widget"""
        filename = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("PDF files", "*.pdf")]
        )
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)
    
    def clear_test_output(self):
        """Clear the test output text area"""
        self.test_output.delete(1.0, tk.END)
    
    def update_status(self, status_widget, message, is_error=False):
        """Update status label with message"""
        color = "red" if is_error else "green"
        status_widget.config(text=message, foreground=color)
        # Clear status after 5 seconds
        self.root.after(5000, lambda: status_widget.config(text=""))
    
    def write_test_output(self, message):
        """Write message to test output area"""
        self.test_output.insert(tk.END, message + "\n")
        self.test_output.see(tk.END)
        self.root.update_idletasks()
    
    # ========== GUI EVENT HANDLERS ==========
    
    def register_user_gui(self):
        """GUI implementation for user registration"""
        user_id = self.user_id_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not user_id:
            self.update_status(self.reg_status, "Error: User ID cannot be empty", True)
            return
        
        try:
            # Show processing
            self.update_status(self.reg_status, "Registering user...")
            
            # Call backend system
            result = self.system.register_user(user_id, password)
            
            if result:
                self.update_status(self.reg_status, f"✓ User '{user_id}' registered successfully!")
                # Clear fields
                self.user_id_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
            else:
                self.update_status(self.reg_status, f"Error: Failed to register user '{user_id}'", True)
                
        except Exception as e:
            self.update_status(self.reg_status, f"Error: {str(e)}", True)
    
    def sign_document_gui(self):
        """GUI implementation for document signing"""
        document_path = self.sign_file_entry.get().strip()
        signer_id = self.signer_id_entry.get().strip()
        password = self.signer_password_entry.get().strip()
        
        if not all([document_path, signer_id]):
            self.update_status(self.sign_status, "Error: Please fill all required fields", True)
            return
        
        if not os.path.exists(document_path):
            self.update_status(self.sign_status, "Error: Document file does not exist", True)
            return
        
        try:
            # Show processing
            self.update_status(self.sign_status, "Signing document...")
            
            # Call backend system
            signature_file = self.system.sign_document(signer_id, document_path, password)
            
            if signature_file:
                self.update_status(self.sign_status, f"✓ Document signed successfully!\nSignature: {signature_file}")
                # Clear fields
                self.sign_file_entry.delete(0, tk.END)
                self.signer_id_entry.delete(0, tk.END)
                self.signer_password_entry.delete(0, tk.END)
            else:
                self.update_status(self.sign_status, "Error: Failed to sign document", True)
                
        except Exception as e:
            self.update_status(self.sign_status, f"Error: {str(e)}", True)
    
    def multi_sign_document_gui(self):
        """GUI implementation for multi-document signing"""
        document_path = self.multi_sign_file_entry.get().strip()
        signer_ids = self.multi_signer_ids_entry.get().strip()
        password_text = self.multi_signer_passwords_entry.get().strip()
        
        if not all([document_path, signer_ids]):
            self.update_status(self.multi_sign_status, "Error: Please fill all required fields", True)
            return
        
        if not os.path.exists(document_path):
            self.update_status(self.multi_sign_status, "Error: Document file does not exist", True)
            return
        
        signers = [s.strip() for s in signer_ids.split(",") if s.strip()]
        if not signers:
            self.update_status(self.multi_sign_status, "Error: Please provide at least one signer ID", True)
            return
        
        # Process passwords
        passwords = None
        if password_text:
            passwords = [p.strip() for p in password_text.split(",") if p.strip()]
            # If number of passwords doesn't match signers, use None for missing ones
            if len(passwords) != len(signers):
                passwords = passwords + [None] * (len(signers) - len(passwords))
                passwords = passwords[:len(signers)]  # Trim if too many
        
        try:
            # Show processing
            self.update_status(self.multi_sign_status, f"Signing document with {len(signers)} signers...")
            
            # Call backend system
            multi_sig_file = self.system.multi_sign_document(signers, document_path, passwords)
            
            if multi_sig_file:
                self.update_status(self.multi_sign_status, f"✓ Document signed by all {len(signers)} signers!\nMulti-signature file: {multi_sig_file}")
                # Clear fields
                self.multi_sign_file_entry.delete(0, tk.END)
                self.multi_signer_ids_entry.delete(0, tk.END)
                self.multi_signer_passwords_entry.delete(0, tk.END)
            else:
                self.update_status(self.multi_sign_status, "Error: Failed to sign document with multiple signers", True)
                
        except Exception as e:
            self.update_status(self.multi_sign_status, f"Error: {str(e)}", True)

    def encrypt_document_gui(self):
        """GUI implementation for document encryption"""
        document_path = self.enc_file_entry.get().strip()
        sender_id = self.sender_id_entry.get().strip()
        recipient_id = self.recipient_id_entry.get().strip()
        
        if not all([document_path, sender_id, recipient_id]):
            self.update_status(self.enc_status, "Error: Please fill all required fields", True)
            return
        
        if not os.path.exists(document_path):
            self.update_status(self.enc_status, "Error: Document file does not exist", True)
            return
        
        try:
            # Show processing
            self.update_status(self.enc_status, "Encrypting document...")
            
            # Call backend system
            encrypted_file = self.system.encrypt_for_recipient(sender_id, document_path, recipient_id)
            
            if encrypted_file:
                self.update_status(self.enc_status, f"✓ Document encrypted successfully!\nEncrypted: {encrypted_file}")
                # Clear fields
                self.enc_file_entry.delete(0, tk.END)
                self.sender_id_entry.delete(0, tk.END)
                self.recipient_id_entry.delete(0, tk.END)
            else:
                self.update_status(self.enc_status, "Error: Failed to encrypt document", True)
                
        except Exception as e:
            self.update_status(self.enc_status, f"Error: {str(e)}", True)
    
    def verify_signature_gui(self):
        """GUI implementation for signature verification"""
        document_path = self.verify_file_entry.get().strip()
        signature_path = self.sig_file_entry.get().strip()
        
        if not all([document_path, signature_path]):
            self.update_status(self.verify_status, "Error: Please select both document and signature files", True)
            return
        
        if not os.path.exists(document_path):
            self.update_status(self.verify_status, "Error: Document file does not exist", True)
            return
        
        if not os.path.exists(signature_path):
            self.update_status(self.verify_status, "Error: Signature file does not exist", True)
            return
        
        try:
            # Show processing
            self.update_status(self.verify_status, "Verifying signature...")
            
            # Call backend system
            is_valid = self.system.verify_signature(document_path, signature_path)
            
            if is_valid:
                self.verify_result.config(text="✓ SIGNATURE VALID - Document is authentic", foreground="green")
                self.update_status(self.verify_status, "Verification completed successfully!")
            else:
                self.verify_result.config(text="✗ SIGNATURE INVALID - Document may be tampered", foreground="red")
                self.update_status(self.verify_status, "Verification failed!", True)
                
        except Exception as e:
            self.update_status(self.verify_status, f"Error: {str(e)}", True)
            self.verify_result.config(text="")

    def verify_symmetric_transfer_gui(self):
        """GUI implementation for symmetric transfer verification"""
        encrypted_file_path = self.sym_verify_file_entry.get().strip()
        shared_key_hex = self.shared_key_entry.get().strip()
        expected_sender = self.expected_sender_entry.get().strip() or None
        
        # Clear previous results
        self.clear_symmetric_verification_results()
        
        if not all([encrypted_file_path, shared_key_hex]):
            self.update_status(self.sym_verify_status, "Error: Please provide encrypted file and shared key", True)
            return
        
        if not os.path.exists(encrypted_file_path):
            self.update_status(self.sym_verify_status, "Error: Encrypted file does not exist", True)
            return
        
        # Validate key format
        try:
            if len(shared_key_hex) != 64:  # 32 bytes in hex
                self.update_status(self.sym_verify_status, "Error: Key must be 64 hex characters (32 bytes)", True)
                return
            aes_key = bytes.fromhex(shared_key_hex)
        except ValueError:
            self.update_status(self.sym_verify_status, "Error: Invalid key format - must be valid hexadecimal", True)
            return
        
        try:
            # Show processing
            self.update_status(self.sym_verify_status, "Verifying document integrity and authenticity...")
            
            # Import and use the symmetric transfer module
            symmetric_module = __import__('modules.symmetric_transfer', fromlist=['reveal_and_verify_file'])
            
            # Verify and decrypt
            result = symmetric_module.SymmetricTransfer.reveal_and_verify_file(
                Path(encrypted_file_path),
                aes_key, 
                expected_sender
            )
            
            # Update verification results
            self.update_symmetric_verification_results(result)
            
            if result["overall_valid"]:
                self.sym_verify_result.config(
                    text="✅ DOCUMENT VERIFIED SUCCESSFULLY", 
                    foreground="green"
                )
                self.update_status(self.sym_verify_status, 
                                f"Verification successful! Decrypted file: {os.path.basename(result['file_path'])}")
            else:
                self.sym_verify_result.config(
                    text="❌ DOCUMENT VERIFICATION FAILED", 
                    foreground="red"
                )
                self.update_status(self.sym_verify_status, "Document verification failed - possible tampering or wrong sender!", True)
                
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.update_status(self.sym_verify_status, error_msg, True)
            self.sym_verify_result.config(text="❌ VERIFICATION ERROR", foreground="red")
    
    def run_all_tests_gui(self):
        """GUI implementation for running all security tests"""
        def run_tests_in_thread():
            try:
                self.write_test_output("🚀 Starting Security Tests...")
                self.write_test_output("=" * 50)
                
                # Run normal workflow test
                self.write_test_output("\n🔒 Test 1: Normal Workflow")
                self.write_test_output("-" * 30)
                self.system.test_normal_workflow()
                self.write_test_output("✓ Normal workflow test completed")
                
                # Run tampered document test
                self.write_test_output("\n🔒 Test 2: Tampered Document Detection")
                self.write_test_output("-" * 30)
                self.system.test_tampered_document()
                self.write_test_output("✓ Tampered document test completed")
                
                # Run wrong recipient test
                self.write_test_output("\n🔒 Test 3: Wrong Recipient Protection")
                self.write_test_output("-" * 30)
                self.system.test_wrong_recipient()
                self.write_test_output("✓ Wrong recipient test completed")
                
                # Run forged signature test
                self.write_test_output("\n🔒 Test 4: Forged Signature Detection")
                self.write_test_output("-" * 30)
                self.system.test_forged_signature()
                self.write_test_output("✓ Forged signature test completed")
                
                # Run multi-signature test
                self.write_test_output("\n🔒 Test 5: Multi-Signature Workflow")
                self.write_test_output("-" * 30)
                self.system.test_multi_signature()
                self.write_test_output("✓ Multi-signature test completed")
                
                self.write_test_output("\n" + "=" * 50)
                self.write_test_output("🎉 ALL SECURITY TESTS COMPLETED SUCCESSFULLY!")
                self.write_test_output("\nSystem Security Status: ✅ SECURE")
                
            except Exception as e:
                self.write_test_output(f"\n❌ Error during testing: {str(e)}")
        
        # Clear previous output
        self.clear_test_output()
        
        # Run tests in a separate thread to avoid freezing the GUI
        test_thread = threading.Thread(target=run_tests_in_thread)
        test_thread.daemon = True
        test_thread.start()


# To run the GUI
if __name__ == "__main__":
    # Make sure to import your DigitalSigningSystem class
    # from digital_signing_system import DigitalSigningSystem
    
    root = tk.Tk()
    
    # Configure style for better appearance
    style = ttk.Style()
    style.configure("Accent.TButton", foreground="white", background="#0078D4")
    
    app = DigitalSigningGUI(root)
    root.mainloop()