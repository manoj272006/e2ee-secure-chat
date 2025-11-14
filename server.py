# server.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import smtplib
import random
import pyotp
import qrcode
import io
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from hashlib import sha256
import secrets
import traceback

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# --- Database config ---
DB_FILE = os.environ.get("DB_FILE", "users.db")
DB_PATH = os.path.abspath(DB_FILE)
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

def get_db_connection():
    """
    Return a sqlite3 connection suitable for use with gunicorn workers.
    Note: sqlite + multiple processes/workers can cause locking; for production use Postgres.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# --- App config (secrets from env only) ---
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587")) if os.environ.get("SMTP_PORT") else None
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.environ.get("TWILIO_PHONE")

# Utility functions
def hash_password(password):
    return sha256(password.encode()).hexdigest()

def generate_otp():
    return str(random.randint(100000, 999999)).zfill(6)

def generate_session_id():
    return secrets.token_urlsafe(32)

def generate_totp_secret():
    return pyotp.random_base32()

def generate_qr_code(username, secret):
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="E2EE Secure Chat"
    )
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return img_str

def verify_totp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)

def send_email_otp(email, otp, otp_type="signup"):
    """Send OTP via email. If SMTP creds not configured, logs OTP instead."""
    try:
        if not (SMTP_SERVER and SMTP_PORT and EMAIL_USER and EMAIL_PASSWORD):
            # Fallback: log OTP to stdout for dev
            print(f"[DEV-FALLBACK] Email OTP for {email}: {otp}")
            return True

        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email

        if otp_type == "2fa":
            msg['Subject'] = "Your E2EE Chat Login Code (2FA)"
            body = f"""
            <html><body style="font-family: Arial, sans-serif;">
                <h2>🔐 Two-Factor Authentication</h2>
                <p>Your login verification code is:</p>
                <h1 style="color: #667eea; letter-spacing: 5px;">{otp}</h1>
                <p>This code will expire in 10 minutes.</p>
            </body></html>
            """
        else:
            msg['Subject'] = "Your E2EE Chat Verification Code"
            body = f"""
            <html><body style="font-family: Arial, sans-serif;">
                <h2>📧 Email Verification</h2>
                <p>Your verification code is:</p>
                <h1 style="color: #667eea; letter-spacing: 5px;">{otp}</h1>
                <p>This code will expire in 10 minutes.</p>
            </body></html>
            """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Email send error:", e)
        traceback.print_exc()
        return False

def send_sms_otp(phone, otp, otp_type="signup"):
    """Send OTP via Twilio. If Twilio creds not configured, logs OTP instead."""
    try:
        if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE):
            print(f"[DEV-FALLBACK] SMS OTP for {phone}: {otp}")
            return True

        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        if otp_type == "2fa":
            message_body = f"🔐 Your E2EE Chat login code: {otp}. Valid for 10 minutes. Don't share this code."
        else:
            message_body = f"Your E2EE Chat verification code: {otp}. Valid for 10 minutes."

        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE,
            to=phone
        )
        return True
    except Exception as e:
        print("SMS send error:", e)
        traceback.print_exc()
        return False

# --- DB Initialization ---
def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    contact TEXT UNIQUE NOT NULL,
                    public_key TEXT NOT NULL,
                    two_fa_enabled INTEGER DEFAULT 0,
                    two_fa_method TEXT DEFAULT NULL,
                    totp_secret TEXT DEFAULT NULL,
                    created_at TEXT NOT NULL
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    encrypted_message TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS otps (
                    username TEXT PRIMARY KEY,
                    contact TEXT NOT NULL,
                    otp TEXT NOT NULL,
                    otp_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )""")

    c.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    otp_verified INTEGER DEFAULT 0
                )""")

    conn.commit()
    conn.close()

# Ensure DB exists when module is imported (so gunicorn workers see it)
try:
    init_db()
    print(f"Initialized DB at {DB_PATH}")
except Exception as e:
    print("Failed to initialize DB at import:", e)
    traceback.print_exc()

# --- Routes ---
@app.route('/')
def home():
    # serve static index.html if present
    index_path = os.path.join(app.static_folder or "static", "index.html")
    if os.path.exists(index_path):
        return send_from_directory(app.static_folder, 'index.html')
    return "🔐 E2EE Secure Chat Server Running (with 2FA: Email/SMS/TOTP)"

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.json or {}
    username = data.get("username")
    contact = data.get("contact")
    if not username or not contact:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if c.fetchone():
            return jsonify({"status": "error", "message": "Username already exists"}), 409

        c.execute("SELECT username FROM users WHERE contact = ?", (contact,))
        existing_user = c.fetchone()
        if existing_user:
            return jsonify({"status": "error", "message": "This email/phone is already registered"}), 409

        otp = generate_otp()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

        c.execute("INSERT OR REPLACE INTO otps (username, contact, otp, otp_type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (username, contact, otp, "signup", created_at, expires_at))
        conn.commit()
    except Exception as e:
        print("DB error in request-otp:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

    is_email = '@' in contact
    success = False
    if is_email:
        success = send_email_otp(contact, otp, "signup")
    else:
        success = send_sms_otp(contact, otp, "signup")

    if success:
        return jsonify({"status": "success", "message": "OTP sent"})
    else:
        return jsonify({"status": "error", "message": "Failed to send OTP"}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json or {}
    username = data.get("username")
    otp = data.get("otp")
    session_id = data.get("session_id")

    if not username or not otp:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT otp, expires_at, otp_type FROM otps WHERE username = ?", (username,))
        result = c.fetchone()
        if not result:
            return jsonify({"status": "error", "message": "OTP not found"}), 404

        stored_otp = result["otp"]
        expires_at = result["expires_at"]
        otp_type = result["otp_type"]

        if datetime.now() > datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
            c.execute("DELETE FROM otps WHERE username = ?", (username,))
            conn.commit()
            return jsonify({"status": "error", "message": "OTP expired"}), 400

        if stored_otp == otp:
            if otp_type == "2fa" and session_id:
                c.execute("UPDATE login_sessions SET otp_verified = 1 WHERE session_id = ? AND username = ?",
                          (session_id, username))
                conn.commit()
            # For signup case we don't create user here; signup endpoint reads presence of this OTP record
            return jsonify({"status": "success", "message": "OTP verified"})
        else:
            return jsonify({"status": "error", "message": "Invalid OTP"}), 401
    except Exception as e:
        print("DB error in verify-otp:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/setup-totp', methods=['POST'])
def setup_totp():
    data = request.json or {}
    username = data.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400
    secret = generate_totp_secret()
    qr_code = generate_qr_code(username, secret)
    return jsonify({
        "status": "success",
        "secret": secret,
        "qr_code": qr_code,
        "manual_entry": secret
    })

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    contact = data.get("contact")
    public_key = data.get("public_key")
    enable_2fa = data.get("enable_2fa", False)
    two_fa_method = data.get("two_fa_method")
    totp_secret = data.get("totp_secret")

    if not username or not password or not contact or not public_key:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    if enable_2fa and not two_fa_method:
        return jsonify({"status": "error", "message": "2FA method required"}), 400

    if enable_2fa and two_fa_method == "totp" and not totp_secret:
        return jsonify({"status": "error", "message": "TOTP secret required"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM otps WHERE username = ? AND otp_type = 'signup'", (username,))
        if not c.fetchone():
            return jsonify({"status": "error", "message": "OTP not verified"}), 401

        c.execute("SELECT username FROM users WHERE contact = ?", (contact,))
        if c.fetchone():
            return jsonify({"status": "error", "message": "This email/phone is already registered"}), 409

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""INSERT INTO users 
                     (username, password_hash, contact, public_key, two_fa_enabled, two_fa_method, totp_secret, created_at) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (username, hash_password(password), contact, public_key,
                   1 if enable_2fa else 0, two_fa_method if enable_2fa else None,
                   totp_secret if enable_2fa and two_fa_method == "totp" else None, created_at))
        c.execute("DELETE FROM otps WHERE username = ?", (username,))
        conn.commit()
        return jsonify({
            "status": "success",
            "message": "Signup successful",
            "two_fa_enabled": bool(enable_2fa),
            "two_fa_method": two_fa_method if enable_2fa else None
        })
    except sqlite3.IntegrityError as e:
        conn.rollback()
        msg = str(e).lower()
        if "username" in msg:
            return jsonify({"status": "error", "message": "Username already exists"}), 409
        if "contact" in msg:
            return jsonify({"status": "error", "message": "This email/phone is already registered"}), 409
        print("IntegrityError on signup:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    except Exception as e:
        conn.rollback()
        print("Error in signup:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"status": "error", "message": "Missing username/password"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT password_hash, two_fa_enabled, two_fa_method, contact, totp_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if not result:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        if result["password_hash"] != hash_password(password):
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        two_fa_enabled = bool(result["two_fa_enabled"])
        two_fa_method = result["two_fa_method"]
        contact = result["contact"]
        totp_secret = result["totp_secret"]

        if not two_fa_enabled:
            return jsonify({"status": "success", "message": "Login successful", "two_fa_required": False})

        session_id = generate_session_id()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

        c.execute("INSERT INTO login_sessions (session_id, username, created_at, expires_at, otp_verified) VALUES (?, ?, ?, ?, ?)",
                  (session_id, username, created_at, expires_at, 0))
        conn.commit()

        if two_fa_method == "totp":
            return jsonify({
                "status": "success",
                "message": "Enter code from Google Authenticator",
                "two_fa_required": True,
                "two_fa_method": "totp",
                "session_id": session_id
            })

        otp = generate_otp()
        c.execute("INSERT OR REPLACE INTO otps (username, contact, otp, otp_type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (username, contact, otp, "2fa", created_at, expires_at))
        conn.commit()
    except Exception as e:
        print("DB error in login:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

    success = False
    if two_fa_method == "email":
        success = send_email_otp(contact, otp, "2fa")
    elif two_fa_method == "sms":
        success = send_sms_otp(contact, otp, "2fa")

    if success:
        masked_contact = contact if '@' in contact else (contact[:3] + "****" + contact[-4:])
        return jsonify({
            "status": "success",
            "message": "2FA code sent",
            "two_fa_required": True,
            "two_fa_method": two_fa_method,
            "session_id": session_id,
            "contact": masked_contact
        })
    else:
        return jsonify({"status": "error", "message": "Failed to send 2FA code"}), 500

@app.route('/verify-2fa-login', methods=['POST'])
def verify_2fa_login():
    data = request.json or {}
    session_id = data.get("session_id")
    username = data.get("username")
    code = data.get("code")

    if not session_id or not username or not code:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT two_fa_method, totp_secret FROM users WHERE username = ?", (username,))
        user_result = c.fetchone()
        if not user_result:
            return jsonify({"status": "error", "message": "User not found"}), 404

        two_fa_method = user_result["two_fa_method"]
        totp_secret = user_result["totp_secret"]

        if two_fa_method == "totp":
            if not verify_totp(totp_secret, code):
                return jsonify({"status": "error", "message": "Invalid code"}), 401
        else:
            c.execute("SELECT otp, expires_at FROM otps WHERE username = ? AND otp_type = '2fa'", (username,))
            otp_result = c.fetchone()
            if not otp_result:
                return jsonify({"status": "error", "message": "OTP not found"}), 404

            stored_otp = otp_result["otp"]
            expires_at = otp_result["expires_at"]
            if datetime.now() > datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
                c.execute("DELETE FROM otps WHERE username = ?", (username,))
                c.execute("DELETE FROM login_sessions WHERE session_id = ?", (session_id,))
                conn.commit()
                return jsonify({"status": "error", "message": "OTP expired"}), 400

            if stored_otp != code:
                return jsonify({"status": "error", "message": "Invalid OTP"}), 401

            c.execute("DELETE FROM otps WHERE username = ? AND otp_type = '2fa'", (username,))

        c.execute("UPDATE login_sessions SET otp_verified = 1 WHERE session_id = ? AND username = ?",
                 (session_id, username))
        conn.commit()
        return jsonify({"status": "success", "message": "Login successful"})
    except Exception as e:
        print("Error in verify-2fa-login:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/toggle-2fa', methods=['POST'])
def toggle_2fa():
    data = request.json or {}
    username = data.get("username")
    enable = data.get("enable", True)
    method = data.get("method")
    totp_secret = data.get("totp_secret")

    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400
    if enable and not method:
        return jsonify({"status": "error", "message": "2FA method required"}), 400
    if enable and method == "totp" and not totp_secret:
        return jsonify({"status": "error", "message": "TOTP secret required"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        if enable:
            c.execute("UPDATE users SET two_fa_enabled = 1, two_fa_method = ?, totp_secret = ? WHERE username = ?",
                     (method, totp_secret if method == "totp" else None, username))
        else:
            c.execute("UPDATE users SET two_fa_enabled = 0, two_fa_method = NULL, totp_secret = NULL WHERE username = ?",
                     (username,))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "User not found"}), 404
        conn.commit()
        return jsonify({
            "status": "success",
            "message": f"2FA {'enabled' if enable else 'disabled'}",
            "two_fa_enabled": bool(enable),
            "two_fa_method": method if enable else None
        })
    except Exception as e:
        print("Error in toggle-2fa:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/public-key/<username>', methods=['GET'])
def get_public_key(username):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result:
            return jsonify({"status": "success", "public_key": result["public_key"]})
        else:
            return jsonify({"status": "error", "message": "User not found"}), 404
    except Exception as e:
        print("Error in get_public_key:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json or {}
    sender = data.get("sender")
    receiver = data.get("receiver")
    encrypted_message = data.get("encrypted_message")
    if not sender or not receiver or not encrypted_message:
        return jsonify({"status": "error", "message": "Missing data"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM users WHERE username = ?", (receiver,))
        if not c.fetchone():
            return jsonify({"status": "error", "message": "Receiver not found"}), 404

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO messages (sender, receiver, encrypted_message, timestamp) VALUES (?, ?, ?, ?)",
                  (sender, receiver, encrypted_message, timestamp))
        conn.commit()
        return jsonify({"status": "success", "message": "Message sent"})
    except Exception as e:
        print("Error in send_message:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/messages', methods=['GET'])
def get_messages():
    user1 = request.args.get("user1")
    user2 = request.args.get("user2")
    if not user1 or not user2:
        return jsonify({"status": "error", "message": "Missing users"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("""SELECT sender, receiver, encrypted_message, timestamp FROM messages 
                     WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                     ORDER BY id ASC""", (user1, user2, user2, user1))
        rows = c.fetchall()
        messages = []
        for row in rows:
            messages.append({
                "sender": row["sender"],
                "receiver": row["receiver"],
                "encrypted_message": row["encrypted_message"],
                "timestamp": row["timestamp"]
            })
        return jsonify({"messages": messages})
    except Exception as e:
        print("Error in get_messages:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

@app.route('/users', methods=['GET'])
def get_users():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM users")
        users = [row["username"] for row in c.fetchall()]
        return jsonify({"users": users})
    except Exception as e:
        print("Error in get_users:", e)
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

# Cleanup expired OTPs & sessions (can be called periodically if you set up a scheduler)
def cleanup_expired_data():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("DELETE FROM otps WHERE expires_at < ?", (current_time,))
        c.execute("DELETE FROM login_sessions WHERE expires_at < ?", (current_time,))
        conn.commit()
    except Exception as e:
        print("Error in cleanup_expired_data:", e)
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == '__main__':
    # Local dev helper
    print(f"Starting local Flask dev server (DB at {DB_PATH})")
    port = int(os.environ.get("PORT", 8080))
    # Init DB again for local dev (safe because CREATE TABLE IF NOT EXISTS)
    init_db()
    app.run(host="0.0.0.0", port=port, debug=True)
