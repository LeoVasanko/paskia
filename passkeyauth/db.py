import sqlite3

DB_PATH = "webauthn.db"


def init_database():
    """Initialize the SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            user_id BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Create credentials table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id BLOB NOT NULL,
            public_key BLOB NOT NULL,
            sign_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(credential_id)
        )
        """
    )

    conn.commit()
    conn.close()


def get_user_by_username(username: str) -> dict | None:
    """Get user record by username"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, user_id FROM users WHERE username = ?", (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"id": row[0], "username": row[1], "user_id": row[2]}
    return None


def get_user_by_user_id(user_id: bytes) -> dict | None:
    """Get user record by WebAuthn user ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, user_id FROM users WHERE user_id = ?", (user_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"id": row[0], "username": row[1], "user_id": row[2]}
    return None


def create_user(username: str, user_id: bytes) -> int:
    """Create a new user and return the user ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, user_id) VALUES (?, ?)", (username, user_id)
    )
    user_db_id = cursor.lastrowid
    conn.commit()
    conn.close()
    if user_db_id is None:
        raise RuntimeError("Failed to create user")
    return user_db_id


def store_credential(user_db_id: int, credential_id: bytes, public_key: bytes) -> None:
    """Store a credential for a user"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO credentials (user_id, credential_id, public_key) VALUES (?, ?, ?)",
        (user_db_id, credential_id, public_key),
    )
    conn.commit()
    conn.close()


def get_credential_by_id(credential_id: bytes) -> dict | None:
    """Get credential by credential ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT c.public_key, c.sign_count, u.username
        FROM credentials c
        JOIN users u ON c.user_id = u.id
        WHERE c.credential_id = ?
        """,
        (credential_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"public_key": row[0], "sign_count": row[1], "username": row[2]}
    return None


def get_user_credentials(username: str) -> list[bytes]:
    """Get all credential IDs for a user"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT c.credential_id
        FROM credentials c
        JOIN users u ON c.user_id = u.id
        WHERE u.username = ?
        """,
        (username,),
    )
    rows = cursor.fetchall()
    conn.close()

    return [row[0] for row in rows]


def update_credential_sign_count(credential_id: bytes, sign_count: int) -> None:
    """Update the sign count for a credential"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
        (sign_count, credential_id),
    )
    conn.commit()
    conn.close()
