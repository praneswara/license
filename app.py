from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import secrets
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

# -------------------------------------------------------------------
# Database connection (Neon PostgreSQL)
# -------------------------------------------------------------------
def get_db():
    uri = os.getenv("DATABASE_URL")
    if not uri:
        raise ValueError("DATABASE_URL is not set")
    conn = psycopg2.connect(uri, cursor_factory=RealDictCursor)
    return conn

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token():
    return secrets.token_urlsafe(32)

# -------------------------------------------------------------------
# Initialize tables (runs on startup)
# -------------------------------------------------------------------
def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );
    """)

    conn.commit()
    cursor.close()
    conn.close()

# Run table initialization
init_db()

# -------------------------------------------------------------------
# REGISTER
# -------------------------------------------------------------------
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()

        if not email or '@' not in email:
            return jsonify({'success': False, 'message': 'Invalid email'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

        if not name:
            return jsonify({'success': False, 'message': 'Name is required'}), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Email already registered'}), 400

        password_hash = hash_password(password)

        cursor.execute(
            "INSERT INTO users (email, password_hash, name) VALUES (%s, %s, %s) RETURNING id",
            (email, password_hash, name)
        )
        user_id = cursor.fetchone()["id"]

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {'id': user_id, 'email': email, 'name': name}
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# LOGIN
# -------------------------------------------------------------------
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, email, password_hash, name FROM users WHERE email = %s AND is_active = TRUE",
            (email,)
        )
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

        if hash_password(password) != user["password_hash"]:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

        token = generate_token()
        expires_at = datetime.now() + timedelta(days=30)

        cursor.execute(
            "INSERT INTO sessions (user_id, token, expires_at) VALUES (%s, %s, %s)",
            (user["id"], token, expires_at)
        )

        cursor.execute(
            "UPDATE users SET last_login = %s WHERE id = %s",
            (datetime.now(), user["id"])
        )

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user["id"],
                'email': user["email"],
                'name': user["name"]
            }
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# VERIFY TOKEN
# -------------------------------------------------------------------
@app.route('/api/verify', methods=["POST"])
def verify_token():
    try:
        data = request.get_json()
        token = data.get("token", "")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT u.id, u.email, u.name, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = %s AND s.expires_at > NOW() AND u.is_active = TRUE
        """, (token,))

        result = cursor.fetchone()

        cursor.close()
        conn.close()

        if not result:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401

        return jsonify({
            'success': True,
            'user': {
                'id': result["id"],
                'email': result["email"],
                'name': result["name"]
            }
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# HEALTH
# -------------------------------------------------------------------
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'admin-api'}), 200

# -------------------------------------------------------------------
# RUN (Render uses Gunicorn, not this)
# -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
