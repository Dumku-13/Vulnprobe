from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
import sqlite3
from datetime import datetime
import os
from database import DB_PATH, init_db

app = Flask(__name__)
app.secret_key = "supersecretkey123"

# Setup server-side session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Initialize DB on startup if it doesn't exist
if not os.path.exists(DB_PATH):
    init_db()

@app.after_request
def remove_security_headers(response):
    response.headers.pop('X-Content-Type-Options', None)
    response.headers.pop('X-Frame-Options', None)
    response.headers.pop('Content-Security-Policy', None)
    return response

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = get_db()
        c = conn.cursor()
        
        # VULNERABILITY: SQLi — Raw string formatting in SQL query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            c.execute(query)
            user = c.fetchone()
        except sqlite3.Error as e:
            # Exposing DB errors allows error-based SQLi discovery
            return f"Database error: {e}", 500
            
        if user:
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/donate', methods=['GET', 'POST'])
def donate():
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        amount = request.form.get('amount', '0')
        message = request.form.get('message', '')
        date = datetime.now().strftime("%Y-%m-%d")
        
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO donors (name, email, amount, message, date) VALUES (?, ?, ?, ?, ?)",
                  (name, email, amount, message, date))
        conn.commit()
        
        # VULNERABILITY: XSS — message is reflected via Jinja template using | safe
        return render_template('donate.html', success=True, name=name, message=message)
        
    return render_template('donate.html')

@app.route('/search')
def search():
    donor_id = request.args.get('donor_id')
    donor = None
    
    if donor_id:
        conn = get_db()
        c = conn.cursor()
        
        # VULNERABILITY: IDOR — No access control check on whose record this is
        c.execute("SELECT * FROM donors WHERE id=?", (donor_id,))
        donor = c.fetchone()
        
    return render_template('search.html', donor=donor, searched=bool(donor_id))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
