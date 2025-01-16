# Basic Honeypot with OWASP Top 10 Vulnerabilities

from flask import Flask, request, render_template_string, redirect, url_for, make_response
import sqlite3
import os

app = Flask(__name__)

# Database setup for demonstration purposes
DATABASE = 'honeypot.db'
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, content TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return "<h1>Welcome to the Vulnerable Honeypot</h1><p>Test your skills here!</p>"

# 1. SQL Injection Vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Executing query:", query)
        result = c.execute(query).fetchone()
        conn.close()
        if result:
            return f"Welcome {username}!"
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
    auth_cookie = request.cookies.get('auth')
    if auth_cookie == 'admin':
        return "Welcome Admin! You have full access."
    else:
        response = make_response("You are not authenticated. Try setting the auth cookie to 'admin'.")
        response.set_cookie('auth', 'guest')
        return response

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
        # Get the port from the environment variable
    port = int(os.environ.get("PORT", 5000))
    # Run the app on 0.0.0.0 and the specified port
    app.run(host="0.0.0.0", port=port)
