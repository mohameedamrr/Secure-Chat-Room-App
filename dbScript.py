import sqlite3
import hashlib

conn = sqlite3.connect("securityProject.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    AESKEY TEXT NOT NULL
)
""")

username1, password1 = "ahmed", hashlib.sha256("ahmedpassword".encode()).hexdigest()
username2, password2 = "amr", hashlib.sha256("test".encode()).hexdigest()

cur.execute("INSERT INTO users (username, password, aeskey) VALUES (?, ?, ?)", (username1, password1, ""))
cur.execute("INSERT INTO users (username, password, aeskey) VALUES (?, ?, ?)", (username2, password2, ""))



conn.commit()