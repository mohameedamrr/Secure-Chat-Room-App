import sqlite3
import hashlib

conn = sqlite3.connect("securityProject.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
)
""")

username1, password1 = "ahmed", hashlib.sha256("ahmedpassword".encode()).hexdigest()

cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username1, password1))

conn.commit()