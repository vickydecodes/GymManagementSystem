import sqlite3
from passlib.hash import sha256_crypt

conn = sqlite3.connect('gym.db')
cur = conn.cursor()

cur.execute('''
CREATE TABLE IF NOT EXISTS info(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    username TEXT UNIQUE,
    password TEXT,
    street TEXT,
    city TEXT,
    prof INTEGER,
    phone TEXT
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS trainors(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS receps(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS members(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    plan TEXT,
    trainor TEXT
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS equip(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    count INTEGER
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS plans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    exercise TEXT,
    reps INTEGER,
    sets INTEGER
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS progress(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    date TEXT,
    daily_result TEXT,
    rate INTEGER
)
''')


# Hash the default password
default_password = sha256_crypt.hash("admin123")

# Insert default admin if not exists
cur.execute("SELECT * FROM info WHERE username = ?", ('admin',))
if cur.fetchone() is None:
    cur.execute('''
    INSERT INTO info(name, username, password, street, city, prof, phone)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', ('Admin', 'admin', default_password, 'Street', 'City', 1, '1234567890'))


conn.commit()
conn.close()
print("SQLite DB created successfully!")
