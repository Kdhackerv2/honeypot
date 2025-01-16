from flask import Flask, request, redirect, url_for, make_response
import sqlite3
import os

app = Flask(__name__)

# Database setup for demonstration purposes
DATABASE = 'honeypot.db'

def init_db():
    """Initialize the database and create required tables if they don't exist."""
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
        print("Executing query:", query)  # Debugging log
        try:
            result = c.execute(query).fetchone()
        except Exception as e:
            return f"Error executing query: {e}", 500
        finally:
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
    try:
        if request.method == 'POST':
            message = request.form.get('message', '').strip()  # Ensure message is not empty
            if not message:
                return "Message cannot be empty!", 400
            
            # Insert the message into the database
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("INSERT INTO messages (content) VALUES (?)", (message,))
            conn.commit()
            conn.close()
            return redirect(url_for('xss'))

        # Fetch messages from the database
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        messages = c.execute("SELECT content FROM messages").fetchall()
        conn.close()

        # Render messages
        message_list = ''.join(f'<p>{message[0]}</p>' for message in messages)
        return f'''<form method="POST">
                    Message: <input type="text" name="message"><br>
                    <input type="submit" value="Submit">
                  </form>{message_list}'''
    except Exception as e:
        print(f"Error in /xss: {e}")  # Debugging log
        return f"An error occurred: {e}", 500

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
    # Ensure database is initialized
    if not os.path.exists(DATABASE):
        init_db()
    
    port = int(os.environ.get("PORT", 5000))
    # Run the app on 0.0.0.0 and the specified port
    app.run(host="0.0.0.0", port=port)
