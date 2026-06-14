import sqlite3
import os

DB_PATH = 'donors.db'

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create users table (plaintext passwords for SQLi testing)
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Create donors table
    c.execute('''
        CREATE TABLE donors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            amount REAL NOT NULL,
            message TEXT,
            date TEXT NOT NULL
        )
    ''')
    
    # Seed users
    users = [
        ('admin', 'admin123'),
        ('john', 'password1'),
        ('jane', 'letmein')
    ]
    c.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
    
    # Seed donors
    donors = [
        ('Alice Smith', 'alice@example.com', 500.00, 'Keep up the good work!', '2026-05-01'),
        ('Bob Jones', 'bob@example.com', 100.00, 'For the animals.', '2026-05-02'),
        ('Charlie Brown', 'charlie@example.com', 250.00, 'Happy to help.', '2026-05-03'),
        ('Diana Prince', 'diana@example.com', 1000.00, 'In memory of Steve.', '2026-05-04'),
        ('Evan Wright', 'evan@example.com', 50.00, 'Small donation, big heart.', '2026-05-05')
    ]
    c.executemany('INSERT INTO donors (name, email, amount, message, date) VALUES (?, ?, ?, ?, ?)', donors)
    
    conn.commit()
    conn.close()
    print("[+] Database initialized with seed data.")

if __name__ == '__main__':
    init_db()
