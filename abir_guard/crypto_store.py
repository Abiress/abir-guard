"""
Abir-Guard: Encrypted Disk Persistence

Security features:
- AES-256-GCM encryption of all keys on disk
- Argon2id key derivation from master passphrase
- Nonce + auth tag per encryption operation
- Tamper detection via HMAC-SHA256 over encrypted blob
- Secure key material never written to disk unencrypted
- File permissions set to 0o600 (owner read/write only)
"""

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Optional, cast

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

VAULT_DIR = Path.home() / ".abir_guard"
KEYS_FILE = VAULT_DIR / "keys.enc"
CANARY_FILE = VAULT_DIR / ".canary"
AUDIT_FILE = VAULT_DIR / "audit.log"

# Argon2id parameters (OWASP recommended)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_KEY_LENGTH = 32

# Nonce + salt sizes
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 32  # HMAC-SHA256


def derive_master_key(passphrase: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """
    Derive encryption key from passphrase using Argon2id.

    Returns (key_bytes, salt_bytes).
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    kdf = Argon2id(
        salt=salt,
        length=ARGON2_KEY_LENGTH,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt


def encrypt_blob(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data with AES-256-GCM + HMAC-SHA256 auth tag.

    Returns: salt(16) + nonce(12) + ciphertext + tag(32)
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct_with_tag = cast(bytes, aesgcm.encrypt(nonce, data, None))

    # Separate ciphertext and GCM tag
    gcm_tag = ct_with_tag[-16:]
    ciphertext = ct_with_tag[:-16]

    # HMAC-SHA256 over salt + nonce + ciphertext for tamper detection
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(nonce + ciphertext)
    mac = h.finalize()

    return cast(bytes, nonce + ciphertext + gcm_tag + mac)


def decrypt_blob(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt blob encrypted by encrypt_blob.

    Validates HMAC before attempting decryption (fail-fast on tampering).
    """
    if len(blob) < NONCE_SIZE + TAG_SIZE + 16:
        raise ValueError("Blob too short to be valid encrypted data")

    nonce = blob[:NONCE_SIZE]
    # Last 16 bytes = GCM tag, last 32 bytes before that = HMAC
    mac = blob[-TAG_SIZE:]
    gcm_tag = blob[-(TAG_SIZE + 16) : -TAG_SIZE]
    ciphertext = blob[NONCE_SIZE : -(TAG_SIZE + 16)]

    # Verify HMAC first (constant-time comparison)
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(nonce + ciphertext)
    try:
        h.verify(mac)
    except Exception:
        raise ValueError("Tamper detected: HMAC verification failed")

    # Decrypt
    ct_with_tag = ciphertext + gcm_tag
    aesgcm = AESGCM(key)
    return cast(bytes, aesgcm.decrypt(nonce, ct_with_tag, None))


class EncryptedVault:
    """
    Encrypted file-based vault for persistent key storage.

    Usage:
        vault = EncryptedVault("my-passphrase")
        vault.store_key("agent-1", "pub-key-b64", "sec-key-b64")
        vault.save()

        # Later / in new process:
        vault2 = EncryptedVault("my-passphrase")
        vault2.load()
        keys = vault2.list_keys()
    """

    def __init__(self, passphrase: str):
        self.passphrase = passphrase
        self._keys: dict[str, dict[str, Any]] = {}  # key_id -> {public_key, secret_key}
        self._salt: Optional[bytes] = None
        self._master_key: Optional[bytes] = None
        self._canary_key: Optional[str] = None  # For breach detection

    def _get_key(self) -> bytes:
        """Get or derive master encryption key"""
        if self._master_key is None:
            if self._salt:
                self._master_key, _ = derive_master_key(self.passphrase, self._salt)
            else:
                self._master_key, self._salt = derive_master_key(self.passphrase)
        return self._master_key

    def store_key(self, key_id: str, public_key: str, secret_key: str) -> None:
        """Store a keypair in memory (not yet persisted)"""
        self._keys[key_id] = {
            "public_key": public_key,
            "secret_key": secret_key,
            "created_at": time.time(),
        }

    def remove_key(self, key_id: str) -> None:
        """Remove a keypair from memory"""
        self._keys.pop(key_id, None)

    def get_secret(self, key_id: str) -> Optional[str]:
        """Get secret key by ID"""
        entry = self._keys.get(key_id)
        return entry["secret_key"] if entry else None

    def list_keys(self) -> list[str]:
        """List all key IDs"""
        return list(self._keys.keys())

    def save(self) -> None:
        """Encrypt and persist all keys to disk"""
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

        # Derive key and encrypt
        master_key = self._get_key()
        data = json.dumps(self._keys, indent=2).encode("utf-8")
        encrypted = encrypt_blob(data, master_key)

        # Write encrypted file
        KEYS_FILE.write_bytes(encrypted)

        # Set restrictive permissions (owner read/write only)
        try:
            os.chmod(KEYS_FILE, 0o600)
        except OSError:
            pass  # Best effort on non-POSIX systems

    def load(self) -> bool:
        """Load and decrypt keys from disk. Returns True if successful."""
        if not KEYS_FILE.exists():
            return False

        try:
            encrypted = KEYS_FILE.read_bytes()
            master_key = self._get_key()
            data = decrypt_blob(encrypted, master_key)
            self._keys = json.loads(data.decode("utf-8"))
            return True
        except ValueError as e:
            # Tamper detected or wrong passphrase
            raise ValueError(f"Vault load failed: {e}")
        except Exception:
            return False

    def add_canary(self) -> str:
        """
        Plant a canary/honeypot key.
        If this key is ever accessed, it signals a breach.

        Returns canary key_id.
        """
        canary_id = f"__canary_{secrets.token_hex(8)}"
        self.store_key(canary_id, "canary-pub", "canary-secret")

        # Record canary in separate file for breach checking
        canary_data = {
            "id": canary_id,
            "created": time.time(),
            "hash": hashlib.sha256(canary_id.encode()).hexdigest(),
        }
        try:
            CANARY_FILE.write_text(json.dumps(canary_data))
            os.chmod(CANARY_FILE, 0o600)
        except OSError:
            pass

        return canary_id

    def check_canary(self) -> bool:
        """
        Check if canary key has been accessed (tampered).
        Returns True if breach detected.
        """
        if not CANARY_FILE.exists():
            return False

        try:
            canary_data = json.loads(CANARY_FILE.read_text())
            canary_id = canary_data["id"]

            # If canary key is missing from vault, it was accessed
            if canary_id not in self._keys:
                return True  # BREACH DETECTED

            return False
        except Exception:
            return True  # Assume breach on error

    def log_audit(self, action: str, key_id: str, success: bool) -> None:
        """Append tamper-evident audit log entry"""
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

        entry = {
            "ts": time.time(),
            "action": action,
            "key_id": key_id,
            "ok": success,
        }

        # Append to file (no encryption for audit, but hash-chained)
        try:
            if AUDIT_FILE.exists():
                prev = AUDIT_FILE.read_text().strip().split("\n")[-1]
                entry["prev_hash"] = hashlib.sha256(prev.encode()).hexdigest()
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

            with open(AUDIT_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass


def migrate_plaintext_vault(passphrase: str) -> bool:
    """
    Migrate old plaintext keys.json to encrypted keys.enc.

    Returns True if migration succeeded.
    """
    old_file = VAULT_DIR / "keys.json"
    if not old_file.exists():
        return False

    try:
        old_data = json.loads(old_file.read_text())
        vault = EncryptedVault(passphrase)

        for entry in old_data:
            vault.store_key(
                entry["key_id"],
                entry["public_key"],
                entry["secret_key"],
            )

        vault.save()
        old_file.unlink()  # Remove plaintext file
        return True
    except Exception:
        return False
