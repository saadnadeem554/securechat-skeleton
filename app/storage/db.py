# storage/db.py

import mysql.connector
import os
import secrets
from common.utils import sha256_hex

# --- Database Configuration (Placeholder) ---
DB_CONFIG = {
    'user': 'scuser',
    'password': 'scpass',
    'host': 'localhost',
    'database': 'securechat'
}

class UserStorage:
    def __init__(self):
        try:
            self.conn = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.conn.cursor()
            self._ensure_table_exists()
        except mysql.connector.Error as err:
            print(f"[DB] Failed to connect to MySQL. Is the service running? Error: {err}")
            self.conn = None
            self.cursor = None

    def _ensure_table_exists(self):
        """Creates the users table with the required schema."""
        if not self.conn: return
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
        if not self.conn: return False
        try:
            # 1. Generate 16-byte random salt
            salt = os.urandom(16)
            
            # 2. Compute salted password hash: hex(SHA256(salt || password))
            salted_password = salt + raw_password.encode('utf-8')
            pwd_hash = sha256_hex(salted_password)
            
            # 3. Store in DB
            add_user = ("INSERT INTO users (email, username, salt, pwd_hash) "
                        "VALUES (%s, %s, %s, %s)")
            user_data = (email, username, salt, pwd_hash)
            
            self.cursor.execute(add_user, user_data)
            self.conn.commit()
            return True
        except mysql.connector.IntegrityError:
            return False
        except mysql.connector.Error:
            return False

    def login_user(self, username: str, raw_password: str) -> bool:
        """Retrieves salt/hash and verifies the provided password."""
        if not self.conn: return False
        
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
        
        return stored_pwd_hash == recomputed_pwd_hash

    def close(self):
        if self.conn:
            self.conn.close()