import os
import hashlib
import time
import json
from typing import Tuple, Optional

class SecurePasswordManager:
    """
    A secure password storage and verification system implementing:
    - Unique salt generation per password
    - Slow key derivation function (custom PBKDF2-like implementation)
    - Secure password verification
    """
    
    def __init__(self, iterations: int = 100000, hash_length: int = 64):
        """
        Initialize the password manager.
        
        Args:
            iterations: Number of hashing iterations (higher = slower = more secure)
            hash_length: Length of the final hash in bytes
        """
        self.iterations = iterations
        self.hash_length = hash_length
        self.storage = {}  # In-memory storage: {username: (salt, hash, iterations)}
    
    def generate_salt(self, length: int = 32) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Args:
            length: Length of salt in bytes
            
        Returns:
            Random salt bytes
        """
        return os.urandom(length)
    
    def slow_hash(self, password: str, salt: bytes, iterations: int) -> bytes:
        """
        Custom implementation of a slow key derivation function.
        Similar to PBKDF2 but implemented from scratch.
        
        Args:
            password: The password to hash
            salt: Unique salt for this password
            iterations: Number of iterations for the slow hash
            
        Returns:
            Derived key bytes
        """
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Initial hash: SHA-256(password || salt)
        current_hash = hashlib.sha256(password_bytes + salt).digest()
        
        # Iteratively hash to make it computationally expensive
        for i in range(iterations - 1):
            # Use HMAC-like construction: hash(current_hash || password || salt || iteration)
            current_hash = hashlib.sha256(
                current_hash + password_bytes + salt + i.to_bytes(4, 'big')
            ).digest()
        
        # Final hash with length extension
        if self.hash_length > 32:
            # Use multiple SHA-256 rounds to extend length
            extended_hash = current_hash
            blocks_needed = (self.hash_length + 31) // 32
            
            for block in range(1, blocks_needed):
                extended_hash += hashlib.sha256(
                    current_hash + block.to_bytes(4, 'big')
                ).digest()
            
            return extended_hash[:self.hash_length]
        else:
            return current_hash[:self.hash_length]
    
    def hash_password(self, password: str) -> Tuple[bytes, bytes]:
        """
        Hash a password with a new random salt.
        
        Args:
            password: Password to hash
            
        Returns:
            Tuple of (salt, hash)
        """
        salt = self.generate_salt()
        password_hash = self.slow_hash(password, salt, self.iterations)
        return salt, password_hash
    
    def verify_password(self, password: str, salt: bytes, 
                       stored_hash: bytes, iterations: int) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Password to verify
            salt: Salt used for the stored hash
            stored_hash: The stored password hash
            iterations: Number of iterations used for stored hash
            
        Returns:
            True if password matches, False otherwise
        """
        # Hash the provided password with the same salt and iterations
        computed_hash = self.slow_hash(password, salt, iterations)
        
        # Constant-time comparison to prevent timing attacks
        return self._constant_time_compare(computed_hash, stored_hash)
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time to prevent timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Register a new user with a password.
        
        Args:
            username: Username
            password: Password to store
            
        Returns:
            True if successful, False if user already exists
        """
        if username in self.storage:
            return False
        
        salt, password_hash = self.hash_password(password)
        self.storage[username] = (salt, password_hash, self.iterations)
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a user.
        
        Args:
            username: Username
            password: Password to verify
            
        Returns:
            True if authentication successful, False otherwise
        """
        if username not in self.storage:
            # Perform a dummy hash to prevent timing attacks
            self.slow_hash(password, b'dummy_salt_32bytes_long_enough!', self.iterations)
            return False
        
        salt, stored_hash, iterations = self.storage[username]
        return self.verify_password(password, salt, stored_hash, iterations)
    
    def change_password(self, username: str, old_password: str, 
                       new_password: str) -> bool:
        """
        Change a user's password.
        
        Args:
            username: Username
            old_password: Current password
            new_password: New password
            
        Returns:
            True if successful, False if authentication failed
        """
        if not self.authenticate_user(username, old_password):
            return False
        
        salt, password_hash = self.hash_password(new_password)
        self.storage[username] = (salt, password_hash, self.iterations)
        return True
    
    def export_storage(self, filename: str):
        """
        Export user storage to a file (for persistence).
        
        Args:
            filename: Output filename
        """
        export_data = {}
        for username, (salt, hash_val, iterations) in self.storage.items():
            export_data[username] = {
                'salt': salt.hex(),
                'hash': hash_val.hex(),
                'iterations': iterations
            }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def import_storage(self, filename: str):
        """
        Import user storage from a file.
        
        Args:
            filename: Input filename
        """
        with open(filename, 'r') as f:
            import_data = json.load(f)
        
        self.storage = {}
        for username, data in import_data.items():
            salt = bytes.fromhex(data['salt'])
            hash_val = bytes.fromhex(data['hash'])
            iterations = data['iterations']
            self.storage[username] = (salt, hash_val, iterations)


def demonstrate_system():
    """Demonstration of the password management system."""
    
    print("=" * 60)
    print("Secure Password Storage and Verification System")
    print("=" * 60)
    
    # Initialize the password manager
    pm = SecurePasswordManager(iterations=100000)
    
    print("\n1. Registering users...")
    print("-" * 60)
    
    # Register some users
    users = [
        ("alice", "MySecureP@ssw0rd!"),
        ("bob", "B0b_L0vesSecur1ty"),
        ("charlie", "Ch@rl13_2024")
    ]
    
    for username, password in users:
        start_time = time.time()
        success = pm.register_user(username, password)
        elapsed = time.time() - start_time
        
        if success:
            print(f"✓ Registered '{username}' (took {elapsed:.3f}s)")
        else:
            print(f"✗ Failed to register '{username}' (already exists)")
    
    print("\n2. Authenticating users with correct passwords...")
    print("-" * 60)
    
    for username, password in users:
        start_time = time.time()
        authenticated = pm.authenticate_user(username, password)
        elapsed = time.time() - start_time
        
        status = "✓ SUCCESS" if authenticated else "✗ FAILED"
        print(f"{status}: '{username}' (took {elapsed:.3f}s)")
    
    print("\n3. Testing with incorrect passwords...")
    print("-" * 60)
    
    wrong_attempts = [
        ("alice", "WrongPassword123"),
        ("bob", "incorrect"),
        ("nonexistent", "anypassword")
    ]
    
    for username, password in wrong_attempts:
        authenticated = pm.authenticate_user(username, password)
        status = "✗ Correctly rejected" if not authenticated else "✓ SECURITY ISSUE!"
        print(f"{status}: '{username}' with wrong password")
    
    print("\n4. Changing password...")
    print("-" * 60)
    
    old_pass = "MySecureP@ssw0rd!"
    new_pass = "NewP@ssword2024!"
    
    success = pm.change_password("alice", old_pass, new_pass)
    print(f"✓ Password changed for 'alice': {success}")
    
    # Verify old password no longer works
    old_auth = pm.authenticate_user("alice", old_pass)
    print(f"✗ Old password rejected: {not old_auth}")
    
    # Verify new password works
    new_auth = pm.authenticate_user("alice", new_pass)
    print(f"✓ New password accepted: {new_auth}")
    
    print("\n5. Inspecting stored data...")
    print("-" * 60)
    
    username = "alice"
    if username in pm.storage:
        salt, hash_val, iterations = pm.storage[username]
        print(f"User: {username}")
        print(f"  Salt (hex): {salt.hex()[:32]}... ({len(salt)} bytes)")
        print(f"  Hash (hex): {hash_val.hex()[:32]}... ({len(hash_val)} bytes)")
        print(f"  Iterations: {iterations:,}")
    
    print("\n6. Exporting/Importing storage...")
    print("-" * 60)
    
    # Export
    pm.export_storage("password_storage.json")
    print("✓ Exported storage to 'password_storage.json'")
    
    # Create new manager and import
    pm2 = SecurePasswordManager()
    pm2.import_storage("password_storage.json")
    print("✓ Imported storage to new manager instance")
    
    # Verify authentication still works
    auth_test = pm2.authenticate_user("bob", "B0b_L0vesSecur1ty")
    print(f"✓ Authentication works after import: {auth_test}")
    
    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)


if __name__ == "__main__":
    demonstrate_system()