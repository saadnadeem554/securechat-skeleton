# storage/db.py

import mysql.connector
import os
import secrets
from common.utils import sha256_hex

# --- Database Configuration (Placeholder) ---
DB_CONFIG = {
    'user': 'securechat_user',
    'password': 'supersecurepassword',
    'host': '127.0.0.1',
    'database': 'securechat_db'
}

class UserStorage:
    def __init__(self):
        # NOTE: This is conceptual. Actual implementation needs proper connection handling.
        try:
            self.conn = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.conn.cursor()
            self._ensure_table_exists()
        except mysql.connector.Error as err:
            print(f"Failed to connect to MySQL: {err}")
            self.conn = None
            self.cursor = None

    def _ensure_table_exists(self):
        """Creates the users table with the required schema."""
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            PRIMARY KEY (email)
        )
        """
        self.cursor.execute(create_table_query)
        self.conn.commit()
        
    def register_user(self, email: str, username: str, raw_password: str) -> bool:
        """Generates salt, computes hash (hex(SHA256(salt || pwd))), and stores new user."""
        try:
            # 1. Generate 16-byte random salt
            salt = os.urandom(16)
            
            # 2. Compute salted password hash
            salted_password = salt + raw_password.encode('utf-8')
            pwd_hash = sha256_hex(salted_password)
            
            # 3. Store in DB
            add_user = ("INSERT INTO users (email, username, salt, pwd_hash) "
                        "VALUES (%s, %s, %s, %s)")
            user_data = (email, username, salt, pwd_hash)
            
            self.cursor.execute(add_user, user_data)
            self.conn.commit()
            print(f"[DB] User '{username}' registered successfully.")
            return True
        except mysql.connector.IntegrityError:
            print(f"[DB] Error: Username or email already registered.")
            return False
        except mysql.connector.Error as err:
            print(f"[DB] Database error during registration: {err}")
            return False

    def login_user(self, username: str, raw_password: str) -> bool:
        """Retrieves salt/hash and verifies the provided password."""
        
        query = "SELECT salt, pwd_hash FROM users WHERE username = %s"
        self.cursor.execute(query, (username,))
        result = self.cursor.fetchone()
        
        if not result:
            return False # User not found
            
        stored_salt: bytes = result[0]
        stored_pwd_hash: str = result[1]
        
        # Recompute hash with stored salt
        salted_password = stored_salt + raw_password.encode('utf-8')
        recomputed_pwd_hash = sha256_hex(salted_password)
        
        # Verify match
        return stored_pwd_hash == recomputed_pwd_hash

    def close(self):
        if self.conn:
            self.conn.close()