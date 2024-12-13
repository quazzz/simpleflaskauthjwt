from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import jwt
from functools import wraps
import datetime
app = Flask(__name__)
app.secret_key = 'your_secret_key'

DB_PATH = './users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')  # Retrieve token from cookies
        if not token:
            return redirect(url_for('login'))

        try:
            jwt.decode(token, app.secret_key, algorithms=['HS256'])  # Validate token
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()

        if user:
            token = jwt.encode(
                {'username': username, 'exp': datetime.datetime.utc() + datetime.timedelta(hours=1)},
                app.secret_key,
                algorithm='HS256'
            )
            response = redirect(url_for('home'))
            response.set_cookie('token', token)  
            response.set_cookie('name',username)
     
            return response

        return jsonify({'error': 'Invalid credentials'}), 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400
        finally:
            conn.close()

        return jsonify({'message': 'Registration successful'})

    return render_template('register.html')

@app.route('/home', methods=['GET'])
@login_required
def home():
    return render_template('main.html')

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
