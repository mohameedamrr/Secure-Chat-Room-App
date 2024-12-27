import sqlite3
import hashlib
import os

conn = sqlite3.connect("server/securityProject.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS keys(
    id INTEGER PRIMARY KEY,
    private_key VARCHAR(255) NOT NULL,
    public_key VARCHAR(255) NOT NULL
)
""")
salt1 = os.urandom(16)
salt2 = os.urandom(16)
username1, password1 = "ahmed", hashlib.sha256("ahmedpassword".encode() + salt1).hexdigest()
username2, password2 = "amr", hashlib.sha256("test".encode() + salt2).hexdigest()

cur.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", (username1, password1, salt1))
cur.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", (username2, password2, salt2))

conn.commit()