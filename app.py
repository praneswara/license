from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import psycopg
from psycopg.rows import dict_row
import hashlib
import secrets
from datetime import datetime, timedelta
import os
import string

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# -------------------------------------------------------------------
# Database connection (Neon PostgreSQL)
# -------------------------------------------------------------------
def get_db():
    uri = os.getenv("DATABASE_URL")
    if not uri:
        raise ValueError("DATABASE_URL is not set")
    conn = psycopg.connect(uri, row_factory=dict_row)
    return conn

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token():
    return secrets.token_urlsafe(32)

def generate_product_key():
    """Generate a unique product key in format: XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    # Remove confusing characters
    chars = chars.replace('0', '').replace('O', '').replace('I', '').replace('1', '')
    
    key_parts = []
    for _ in range(4):
        part = ''.join(secrets.choice(chars) for _ in range(4))
        key_parts.append(part)
    
    return '-'.join(key_parts)

def get_subscription_days(subscription_type):
    """Get number of days for subscription type"""
    subscription_map = {
        '7days': 7,
        '1month': 30,
        '1year': 365
    }
    return subscription_map.get(subscription_type.lower(), 0)

# -------------------------------------------------------------------
# Initialize tables (runs on startup)
# -------------------------------------------------------------------
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
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
    
    # Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );
    """)
    
    # Product keys table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS product_keys (
            id SERIAL PRIMARY KEY,
            product_key VARCHAR(50) UNIQUE NOT NULL,
            subscription_type VARCHAR(20) NOT NULL,
            user_email VARCHAR(255),
            user_name TEXT,
            device_id TEXT,
            device_info TEXT,
            start_date TIMESTAMP NOT NULL,
            end_date TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    # Product key requests table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS product_key_requests (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            name TEXT,
            subscription_type VARCHAR(20) NOT NULL,
            device_id TEXT,
            status VARCHAR(20) DEFAULT 'pending',
            product_key VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
# PRODUCT KEY REQUEST (Auto-generates product key)
# -------------------------------------------------------------------
@app.route('/api/product-key/request', methods=['POST'])
def request_product_key():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        name = data.get('name', '').strip()
        subscription_type = data.get('subscription_type', '').strip()
        device_id = data.get('device_id', '').strip()

        if not email or '@' not in email:
            return jsonify({'success': False, 'message': 'Invalid email'}), 400

        if subscription_type not in ['7days', '1month', '1year']:
            return jsonify({'success': False, 'message': 'Invalid subscription type'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Check if user already has an active product key
        cursor.execute(
            """SELECT product_key, end_date FROM product_keys 
               WHERE user_email = %s AND is_active = TRUE AND end_date > NOW()""",
            (email,)
        )
        existing_key = cursor.fetchone()
        if existing_key:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'You already have an active product key',
                'product_key': existing_key['product_key']
            }), 400

        # Generate unique product key
        product_key = generate_product_key()
        max_attempts = 10
        attempts = 0
        
        while attempts < max_attempts:
            cursor.execute("SELECT id FROM product_keys WHERE product_key = %s", (product_key,))
            if not cursor.fetchone():
                break
            product_key = generate_product_key()
            attempts += 1

        if attempts >= max_attempts:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Failed to generate unique product key'}), 500

        # Calculate dates
        start_date = datetime.now()
        days = get_subscription_days(subscription_type)
        end_date = start_date + timedelta(days=days)

        # Create product key record
        cursor.execute(
            """INSERT INTO product_keys 
               (product_key, subscription_type, user_email, user_name, device_id, start_date, end_date, is_active)
               VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE) RETURNING id""",
            (product_key, subscription_type, email, name, device_id, start_date, end_date)
        )
        key_id = cursor.fetchone()["id"]

        # Create request record (for tracking)
        cursor.execute(
            """INSERT INTO product_key_requests (email, name, subscription_type, device_id, status, product_key)
               VALUES (%s, %s, %s, %s, 'approved', %s) RETURNING id""",
            (email, name, subscription_type, device_id, product_key)
        )
        request_id = cursor.fetchone()["id"]

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Product key generated successfully',
            'product_key': product_key,
            'subscription_type': subscription_type,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'request_id': request_id
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# GENERATE PRODUCT KEY (Admin function - auto-generate on request)
# -------------------------------------------------------------------
@app.route('/api/product-key/generate', methods=['POST'])
def generate_product_key_endpoint():
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        email = data.get('email')
        name = data.get('name')
        subscription_type = data.get('subscription_type')
        device_id = data.get('device_id', '')

        if not subscription_type or subscription_type not in ['7days', '1month', '1year']:
            return jsonify({'success': False, 'message': 'Invalid subscription type'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Generate unique product key
        product_key = generate_product_key()
        max_attempts = 10
        attempts = 0
        
        while attempts < max_attempts:
            cursor.execute("SELECT id FROM product_keys WHERE product_key = %s", (product_key,))
            if not cursor.fetchone():
                break
            product_key = generate_product_key()
            attempts += 1

        if attempts >= max_attempts:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Failed to generate unique product key'}), 500

        # Calculate dates
        start_date = datetime.now()
        days = get_subscription_days(subscription_type)
        end_date = start_date + timedelta(days=days)

        # Create product key record
        cursor.execute(
            """INSERT INTO product_keys 
               (product_key, subscription_type, user_email, user_name, device_id, start_date, end_date, is_active)
               VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE) RETURNING id""",
            (product_key, subscription_type, email, name, device_id, start_date, end_date)
        )
        key_id = cursor.fetchone()["id"]

        # Update request if request_id provided
        if request_id:
            cursor.execute(
                """UPDATE product_key_requests 
                   SET status = 'approved', product_key = %s, updated_at = CURRENT_TIMESTAMP
                   WHERE id = %s""",
                (product_key, request_id)
            )

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Product key generated successfully',
            'product_key': product_key,
            'subscription_type': subscription_type,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# VALIDATE PRODUCT KEY
# -------------------------------------------------------------------
@app.route('/api/product-key/validate', methods=['POST'])
def validate_product_key():
    try:
        data = request.get_json()
        product_key = data.get('product_key', '').strip().upper()
        device_id = data.get('device_id', '')
        device_info = data.get('device_info', '')

        if not product_key:
            return jsonify({'success': False, 'message': 'Product key is required'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Find product key
        cursor.execute(
            """SELECT * FROM product_keys WHERE product_key = %s""",
            (product_key,)
        )
        key_record = cursor.fetchone()

        if not key_record:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid product key'}), 404

        # Check if license is expired
        end_date = key_record["end_date"]
        if datetime.now() > end_date:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'License has expired'}), 400

        # Check if license is active
        if not key_record["is_active"]:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'License is deactivated'}), 400

        # Check device binding - if device_id exists and doesn't match, reject
        if key_record["device_id"] and key_record["device_id"] != device_id:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'This product key is already activated on another device'
            }), 400

        # Update device information if not set or if matching
        if not key_record["device_id"] or key_record["device_id"] == device_id:
            cursor.execute(
                """UPDATE product_keys 
                   SET device_id = %s, device_info = %s, updated_at = CURRENT_TIMESTAMP
                   WHERE id = %s""",
                (device_id, device_info, key_record["id"])
            )
            conn.commit()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Product key is valid',
            'license': {
                'product_key': key_record["product_key"],
                'subscription_type': key_record["subscription_type"],
                'start_date': key_record["start_date"].isoformat(),
                'end_date': key_record["end_date"].isoformat(),
                'user_email': key_record["user_email"],
                'user_name': key_record["user_name"]
            }
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# GET ALL PRODUCT KEY REQUESTS (Admin)
# -------------------------------------------------------------------
@app.route('/api/product-key/requests', methods=['GET'])
def get_product_key_requests():
    try:
        status = request.args.get('status', None)
        
        conn = get_db()
        cursor = conn.cursor()

        if status:
            cursor.execute(
                """SELECT * FROM product_key_requests WHERE status = %s ORDER BY created_at DESC""",
                (status,)
            )
        else:
            cursor.execute("""SELECT * FROM product_key_requests ORDER BY created_at DESC""")

        requests = cursor.fetchall()
        
        # Convert datetime objects to ISO format strings
        result = []
        for req in requests:
            req_dict = dict(req)
            req_dict['created_at'] = req['created_at'].isoformat() if req['created_at'] else None
            req_dict['updated_at'] = req['updated_at'].isoformat() if req['updated_at'] else None
            result.append(req_dict)

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'requests': result}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# GET ALL PRODUCT KEYS (Admin)
# -------------------------------------------------------------------
@app.route('/api/product-keys', methods=['GET'])
def get_product_keys():
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""SELECT * FROM product_keys ORDER BY created_at DESC""")
        keys = cursor.fetchall()

        # Convert datetime objects to ISO format strings
        result = []
        for key in keys:
            key_dict = dict(key)
            key_dict['start_date'] = key['start_date'].isoformat() if key['start_date'] else None
            key_dict['end_date'] = key['end_date'].isoformat() if key['end_date'] else None
            key_dict['created_at'] = key['created_at'].isoformat() if key['created_at'] else None
            key_dict['updated_at'] = key['updated_at'].isoformat() if key['updated_at'] else None
            result.append(key_dict)

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'product_keys': result}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------------------
# ADMIN DASHBOARD (Base URL)
# -------------------------------------------------------------------
@app.route('/', methods=['GET'])
def dashboard():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Get statistics
        cursor.execute("SELECT COUNT(*) as total FROM product_key_requests")
        total_requests = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM product_key_requests WHERE status = 'pending'")
        pending_requests = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM product_key_requests WHERE status = 'approved'")
        approved_requests = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM product_keys")
        total_keys = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM product_keys WHERE is_active = TRUE AND end_date > NOW()")
        active_keys = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(*) as total FROM product_keys WHERE end_date < NOW()")
        expired_keys = cursor.fetchone()['total']

        # Get recent requests
        cursor.execute("""
            SELECT * FROM product_key_requests 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        recent_requests = cursor.fetchall()

        # Get recent product keys
        cursor.execute("""
            SELECT * FROM product_keys 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        recent_keys = cursor.fetchall()

        # Convert datetime objects to strings for template
        for req in recent_requests:
            if req.get('created_at'):
                req['created_at'] = req['created_at'].isoformat() if isinstance(req['created_at'], datetime) else str(req['created_at'])
            if req.get('updated_at'):
                req['updated_at'] = req['updated_at'].isoformat() if isinstance(req['updated_at'], datetime) else str(req['updated_at'])

        for key in recent_keys:
            if key.get('start_date'):
                key['start_date'] = key['start_date'].isoformat() if isinstance(key['start_date'], datetime) else str(key['start_date'])
            if key.get('end_date'):
                key['end_date'] = key['end_date'].isoformat() if isinstance(key['end_date'], datetime) else str(key['end_date'])
            if key.get('created_at'):
                key['created_at'] = key['created_at'].isoformat() if isinstance(key['created_at'], datetime) else str(key['created_at'])

        cursor.close()
        conn.close()

        stats = {
            'total_requests': total_requests,
            'pending_requests': pending_requests,
            'approved_requests': approved_requests,
            'total_keys': total_keys,
            'active_keys': active_keys,
            'expired_keys': expired_keys
        }

        return render_template('dashboard.html', 
                             stats=stats,
                             recent_requests=recent_requests,
                             recent_keys=recent_keys,
                             now=datetime.now())

    except Exception as e:
        return f"Error loading dashboard: {str(e)}", 500

# -------------------------------------------------------------------
# REQUESTS PAGE
# -------------------------------------------------------------------
@app.route('/requests', methods=['GET'])
def requests_page():
    try:
        status = request.args.get('status', None)
        conn = get_db()
        cursor = conn.cursor()

        if status:
            cursor.execute(
                """SELECT * FROM product_key_requests WHERE status = %s ORDER BY created_at DESC""",
                (status,)
            )
        else:
            cursor.execute("""SELECT * FROM product_key_requests ORDER BY created_at DESC""")

        requests = cursor.fetchall()

        # Convert datetime objects to strings
        for req in requests:
            if req.get('created_at'):
                req['created_at'] = req['created_at'].isoformat() if isinstance(req['created_at'], datetime) else str(req['created_at'])

        cursor.close()
        conn.close()

        return render_template('requests.html', requests=requests)

    except Exception as e:
        return f"Error loading requests: {str(e)}", 500

# -------------------------------------------------------------------
# LICENSES PAGE
# -------------------------------------------------------------------
@app.route('/licenses', methods=['GET'])
def licenses_page():
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""SELECT * FROM product_keys ORDER BY created_at DESC""")
        licenses = cursor.fetchall()

        # Convert datetime objects to strings
        now = datetime.now()
        for license in licenses:
            if license.get('start_date'):
                license['start_date'] = license['start_date'].isoformat() if isinstance(license['start_date'], datetime) else str(license['start_date'])
            if license.get('end_date'):
                license['end_date'] = license['end_date'].isoformat() if isinstance(license['end_date'], datetime) else str(license['end_date'])
            if license.get('created_at'):
                license['created_at'] = license['created_at'].isoformat() if isinstance(license['created_at'], datetime) else str(license['created_at'])

        cursor.close()
        conn.close()

        return render_template('licenses.html', licenses=licenses, now=now)

    except Exception as e:
        return f"Error loading licenses: {str(e)}", 500

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

