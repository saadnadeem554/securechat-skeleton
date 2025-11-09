"""MySQL users table + salted hashing (no chat storage).""" 
#raise NotImplementedError("students: implement DB layer")

import os
import sys
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database connection settings
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")

# SQL statement to create the users table
CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255),
    username VARCHAR(255) UNIQUE,
    salt VARBINARY(16),
    pwd_hash CHAR(64)
);
"""

def init_db():
    """Create database tables (if not exist)."""
    try:
        print(f"Connecting to MySQL at {DB_HOST}:{DB_PORT} ...")
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT
        )
        cursor = connection.cursor()

        print("Creating 'users' table if it doesn't exist...")
        cursor.execute(CREATE_USERS_TABLE)
        connection.commit()

        print("✅ Database initialized successfully.")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("❌ Access denied: Check your username or password.")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("❌ Database does not exist.")
        else:
            print(f"❌ MySQL Error: {err}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

if __name__ == "__main__":
    # Allow running `python -m app.storage.db --init`
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_db()
    else:
        print("Usage: python -m app.storage.db --init")
