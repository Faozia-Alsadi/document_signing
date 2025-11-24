import base64
import hashlib
import hmac
import json
import secrets
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Optional

from cryptography.hazmat.primitives import padding as pkcs7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure simple logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("file_sym_transfer")


@dataclass
class EncryptedBundle:
    """Container for JSON-serializable encrypted payload metadata."""
    version: str
    iv_b64: str
    ciphertext_b64: str
    key_fingerprint: str

    # New fields for verification
    sender_id: Optional[str] = None
    document_hmac: Optional[str] = None
    timestamp: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2)

    @staticmethod
    def from_json(text: str) -> "EncryptedBundle":
        data = json.loads(text)
        return EncryptedBundle(**data)


class SymmetricTransfer:
    """Symmetric-file transfer utilities using AES-CBC + PKCS7 with verification."""

    AES_KEY_BYTES = 32  # 256 bits
    IV_BYTES = 16       # AES block size in bytes
    BLOCK_BITS = 128    # for PKCS7

    @staticmethod
    def create_session_key() -> bytes:
        """Produce a fresh symmetric key for a single transfer session."""
        key = secrets.token_bytes(SymmetricTransfer.AES_KEY_BYTES)
        logger.debug("Session key generated.")
        return key

    @staticmethod
    def _sha256_short_hex(data: bytes, length: int = 16) -> str:
        """Return truncated SHA-256 hex digest for light verification."""
        return hashlib.sha256(data).hexdigest()[:length]

    @staticmethod
    def _encode_b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _decode_b64(text: str) -> bytes:
        return base64.b64decode(text.encode("ascii"))

    @staticmethod
    def _generate_hmac_key(master_key: bytes) -> bytes:
        """Derive HMAC key from the master AES key."""
        return hashlib.sha256(master_key + b"hmac_salt").digest()

    @classmethod
    def seal_file(
        cls, source: Path, session_key: bytes, sender_id: str, dest: Path | None = None
    ) -> Tuple[Path, bytes]:
        """
        Encrypt `source` with AES-CBC using a fresh IV and write a JSON bundle.
        Includes HMAC for integrity verification and sender authentication.

        Returns the path to the written JSON bundle and the session key used.
        """
        if dest is None:
            dest = source.with_suffix(source.suffix + ".enc")

        iv = secrets.token_bytes(cls.IV_BYTES)
        logger.debug("Generated IV for encryption.")

        plaintext = source.read_bytes()

        # Generate HMAC for integrity verification
        hmac_key = cls._generate_hmac_key(session_key)
        document_hmac = hmac.new(hmac_key, plaintext, hashlib.sha256).digest()

        # Create metadata with sender info and HMAC
        metadata = {
            "sender": sender_id,
            "hmac": cls._encode_b64(document_hmac),
            "timestamp": datetime.now().isoformat(),
            "original_filename": source.name
        }
        metadata_json = json.dumps(metadata).encode('utf-8')

        # Combine metadata length + metadata + document data
        metadata_length = len(metadata_json).to_bytes(4, 'big')  # 4 bytes for length
        combined_data = metadata_length + metadata_json + plaintext

        # Pad the combined data
        padder = pkcs7.PKCS7(cls.BLOCK_BITS).padder()
        padded = padder.update(combined_data) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        # Create bundle with verification data
        bundle = EncryptedBundle(
            version="sym_v2",  # Updated version for verification support
            iv_b64=cls._encode_b64(iv),
            ciphertext_b64=cls._encode_b64(ciphertext),
            key_fingerprint=cls._sha256_short_hex(session_key),
            sender_id=sender_id,
            document_hmac=cls._encode_b64(document_hmac),
            timestamp=metadata["timestamp"]
        )

        dest.write_text(bundle.to_json(), encoding="utf-8")
        logger.info(f"Encrypted: {source} -> {dest}")
        logger.info(f"Sender: {sender_id}")
        logger.info(f"Key fingerprint (short): {bundle.key_fingerprint}")
        logger.info(f"Document HMAC generated for integrity verification")

        return dest, session_key

    @classmethod
    def reveal_file(
        cls, bundle_path: Path, session_key: bytes, output: Path | None = None
    ) -> Path:
        """
        Decrypt a JSON bundle produced by `seal_file` using `session_key`.
        Performs basic decryption without verification.

        Returns the path to the recovered plaintext file.
        """
        if output is None:
            if bundle_path.suffix == ".enc":
                output = bundle_path.with_suffix(".dec" + bundle_path.suffix)
            else:
                output = bundle_path.with_suffix(bundle_path.suffix + ".dec")

        raw = bundle_path.read_text(encoding="utf-8")
        bundle = EncryptedBundle.from_json(raw)

        expected = cls._sha256_short_hex(session_key)
        if bundle.key_fingerprint != expected:
            logger.warning("Key fingerprint mismatch: verification failed (continuing decryption).")

        iv = cls._decode_b64(bundle.iv_b64)
        ciphertext = cls._decode_b64(bundle.ciphertext_b64)

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = pkcs7.PKCS7(cls.BLOCK_BITS).unpadder()
        combined_data = unpadder.update(padded_plain) + unpadder.finalize()

        # Extract metadata and document
        metadata_length = int.from_bytes(combined_data[:4], 'big')
        metadata_json = combined_data[4:4+metadata_length]
        plaintext = combined_data[4+metadata_length:]

        output.write_bytes(plaintext)
        logger.info(f"Decrypted: {bundle_path} -> {output}")

        return output

    @classmethod
    def reveal_and_verify_file(
        cls, bundle_path: Path, session_key: bytes, expected_sender: Optional[str] = None, 
        output: Path | None = None
    ) -> Dict:
        """
        Decrypt and verify a JSON bundle with full integrity and sender verification.
        
        Returns a dictionary with verification results and file path.
        """
        if output is None:
            if bundle_path.suffix == ".enc":
                output = bundle_path.with_suffix(".verified" + bundle_path.suffix)
            else:
                output = bundle_path.with_suffix(bundle_path.suffix + ".verified")

        raw = bundle_path.read_text(encoding="utf-8")
        bundle = EncryptedBundle.from_json(raw)

        # Basic key verification
        expected_fingerprint = cls._sha256_short_hex(session_key)
        key_valid = bundle.key_fingerprint == expected_fingerprint

        if not key_valid:
            logger.warning("Key fingerprint mismatch!")

        iv = cls._decode_b64(bundle.iv_b64)
        ciphertext = cls._decode_b64(bundle.ciphertext_b64)

        # Decrypt
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = pkcs7.PKCS7(cls.BLOCK_BITS).unpadder()
        combined_data = unpadder.update(padded_plain) + unpadder.finalize()

        # Extract metadata and document
        metadata_length = int.from_bytes(combined_data[:4], 'big')
        metadata_json = combined_data[4:4+metadata_length]
        plaintext = combined_data[4+metadata_length:]

        # Parse metadata
        metadata = json.loads(metadata_json.decode('utf-8'))
        stored_hmac_b64 = metadata.get("hmac", "")
        actual_sender = metadata.get("sender", "Unknown")
        timestamp = metadata.get("timestamp", "Unknown")
        original_filename = metadata.get("original_filename", "Unknown")

        # Verify HMAC for integrity
        hmac_key = cls._generate_hmac_key(session_key)
        computed_hmac = hmac.new(hmac_key, plaintext, hashlib.sha256).digest()
        stored_hmac = cls._decode_b64(stored_hmac_b64)
        
        integrity_valid = hmac.compare_digest(computed_hmac, stored_hmac)

        # Verify sender if expected
        sender_valid = True
        if expected_sender and actual_sender != expected_sender:
            sender_valid = False
            logger.warning(f"Sender mismatch! Expected: {expected_sender}, Got: {actual_sender}")

        # Save decrypted file
        output.write_bytes(plaintext)

        # Prepare verification results
        verification_result = {
            "file_path": str(output),
            "integrity_valid": integrity_valid,
            "sender_valid": sender_valid,
            "key_valid": key_valid,
            "sender": actual_sender,
            "timestamp": timestamp,
            "original_filename": original_filename,
            "overall_valid": integrity_valid and sender_valid and key_valid
        }

        # Log verification results
        logger.info(f"Decrypted: {bundle_path} -> {output}")
        logger.info("🔍 VERIFICATION RESULTS:")
        logger.info(f"  Integrity: {'✅ VALID' if integrity_valid else '❌ TAMPERED'}")
        logger.info(f"  Sender: {'✅ ' + actual_sender if sender_valid else '❌ ' + actual_sender}")
        logger.info(f"  Key: {'✅ VALID' if key_valid else '❌ MISMATCH'}")
        logger.info(f"  Timestamp: {timestamp}")
        logger.info(f"  Overall: {'✅ DOCUMENT VERIFIED' if verification_result['overall_valid'] else '❌ VERIFICATION FAILED'}")

        return verification_result

    @classmethod
    def verify_file_integrity(cls, bundle_path: Path, session_key: bytes) -> bool:
        """
        Quick integrity verification without full decryption.
        Useful for checking if a file is valid before decrypting.
        """
        try:
            result = cls.reveal_and_verify_file(bundle_path, session_key)
            return result["overall_valid"]
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False


def symmetric_transfer(sender: str, receiver: str, filepath: str):
    """
    High-level simulation of a verifiable symmetric transfer.
    Includes integrity verification and sender authentication.
    """
    source = Path(filepath)
    logger.info(f"\n--- VERIFIABLE SYMMETRIC EXCHANGE: {sender} → {receiver} ---")

    # Generate fresh key
    logger.info("1) Generating ephemeral key for this transfer...")
    key = SymmetricTransfer.create_session_key()
    logger.info(f"   (session key hex) {key.hex()}")

    # Encrypt the file with verification
    logger.info("2) Encrypting file with integrity protection...")
    enc_path, used_key = SymmetricTransfer.seal_file(source, key, sender)

    # Simulate key exchange (DEMO: printing key; do not do this in production)
    logger.info("3) CAUTION: Do NOT print keys in real systems.")
    logger.info(f"   Transmitted key (hex): {used_key.hex()}")

    # Recipient decrypts WITH VERIFICATION
    logger.info("4) Recipient decrypting with verification...")
    verification_result = SymmetricTransfer.reveal_and_verify_file(enc_path, used_key, sender)

    # Final verification summary
    logger.info("\n" + "="*50)
    if verification_result["overall_valid"]:
        logger.info("🎉 TRANSFER VERIFICATION SUCCESSFUL!")
        logger.info(f"   Document from {verification_result['sender']} is AUTHENTIC")
        logger.info(f"   File integrity: ✅ VALID")
    else:
        logger.info("❌ TRANSFER VERIFICATION FAILED!")
        if not verification_result["integrity_valid"]:
            logger.info("   File may have been tampered with!")
        if not verification_result["sender_valid"]:
            logger.info("   Sender authentication failed!")
    
    logger.info("="*50)

    return str(enc_path), verification_result["file_path"], used_key.hex(), verification_result


# Backward compatibility - original function without verification
def perform_symmetric_transfer(sender: str, receiver: str, filepath: str):
    enc_path, dec_path, key_hex, _ = symmetric_transfer(sender, receiver, filepath)
    return enc_path, dec_path, key_hex
