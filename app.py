# Basic Honeypot with OWASP Top 10 Vulnerabilities

from flask import Flask, request, redirect, url_for, make_response
import sqlite3
import os

app = Flask(__name__)

# Database setup for demonstration purposes
DATABASE = 'honeypot.db'

def init_db():
    """Initializes the database and creates a test user."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, content TEXT)''')
    # Insert a test user (admin:admin123)
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    """Home page."""
    return "<h1>Welcome to the Vulnerable Honeypot</h1><p>Test your skills here!</p>"

# 1. SQL Injection Vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    """A deliberately vulnerable login page."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return "Both username and password are required!", 400

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        # Vulnerable query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Executing query: {query}")  # Debugging log
        
        try:
            result = c.execute(query).fetchone()
            print(f"Query Result: {result}")  # Debugging log
        except Exception as e:
            conn.close()
            print(f"Error executing query: {e}")
            return f"Database error: {e}", 500
        
        conn.close()

        if result:
            return f"Welcome {username}! You are logged in."
        else:
            return "Invalid credentials. Try again."

    return '''<form method="POST">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
              </form>'''

# 2. Cross-Site Scripting (XSS) Vulnerability
@app.route('/xss', methods=['GET', 'POST'])
def xss():
    """A page vulnerable to XSS."""
    if request.method == 'POST':
        message = request.form['message']
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO messages (content) VALUES (?)", (message,))
        conn.commit()
        conn.close()
        return redirect(url_for('xss'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    messages = c.execute("SELECT content FROM messages").fetchall()
    conn.close()
    message_list = ''.join(f'<p>{message[0]}</p>' for message in messages)
    return f'''<form method="POST">
                Message: <input type="text" name="message"><br>
                <input type="submit" value="Submit">
              </form>{message_list}'''

# 3. Insecure Authentication
@app.route('/insecure-auth')
def insecure_auth():
    """A deliberately insecure authentication mechanism."""
    auth_cookie = request.cookies.get('auth')
    if auth_cookie == 'admin':
        return "Welcome Admin! You have full access."
    else:
        response = make_response("You are not authenticated. Try setting the auth cookie to 'admin'.")
        response.set_cookie('auth', 'guest')
        return response

if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()
    # Run the app on 0.0.0.0 for external access
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
