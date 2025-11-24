import json
from datetime import datetime

class AuditLogger:
    """Non-repudiation evidence system"""
    
    def __init__(self, log_file="audit_trail.json"):
        self.log_file = log_file
    
    def log_signature_event(self, signer_id, document_path, signature_file, timestamp=None):
        """Log signature creation for non-repudiation"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        event = {
            "event_type": "document_signed",
            "timestamp": timestamp,
            "signer": signer_id,
            "document": document_path,
            "signature_file": signature_file,
            "evidence": {
                "hash_algorithm": "SHA-256",
                "signing_algorithm": "RSA-PSS",
                "key_size": 2048
            }
        }
        
        # Read existing logs or create empty array
        try:
            with open(self.log_file, "r") as f:
                existing_logs = json.load(f)
                if not isinstance(existing_logs, list):
                    # If file exists but isn't a list, start fresh
                    existing_logs = []
        except (FileNotFoundError, json.JSONDecodeError):
            # File doesn't exist or is corrupted, start with empty array
            existing_logs = []
        
        # Append new event to the array
        existing_logs.append(event)
        
        # Write back the complete array
        with open(self.log_file, "w") as f:
            json.dump(existing_logs, f, indent=2)
        
        print(f"📝 Audit log updated: {len(existing_logs)} total events")
    
    def get_audit_trail(self, document_path=None, signer_id=None):
        """Retrieve audit evidence for non-repudiation"""
        events = []
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    event = json.loads(line.strip())
                    if document_path and event["document"] != document_path:
                        continue
                    if signer_id and event["signer"] != signer_id:
                        continue
                    events.append(event)
        except FileNotFoundError:
            pass
        return events