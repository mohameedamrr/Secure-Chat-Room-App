import sqlite3
import hashlib

conn = sqlite3.connect("server/securityProject.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS keys(
    id INTEGER PRIMARY KEY,
    private_key VARCHAR(255) NOT NULL,
    public_key VARCHAR(255) NOT NULL
)
""")

username1, password1 = "ahmed", hashlib.sha256("ahmedpassword".encode()).hexdigest()
username2, password2 = "amr", hashlib.sha256("test".encode()).hexdigest()

cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username1, password1))
cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username2, password2))



conn.commit()