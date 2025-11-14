from flask import Flask, request, jsonify
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
app = Flask(__name__)
CORS(app)

DB_FILE = "users.db"


# Email configuration — MUST set these as env vars on Render, do NOT keep secrets here
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

# Twilio configuration — set via env vars
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.environ.get("TWILIO_PHONE")


# --- DB SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Users table with public keys and contact
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
    
    # Messages table
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    encrypted_message TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )""")
    
    # OTP table for both signup and 2FA
    c.execute("""CREATE TABLE IF NOT EXISTS otps (
                    username TEXT PRIMARY KEY,
                    contact TEXT NOT NULL,
                    otp TEXT NOT NULL,
                    otp_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )""")
    
    # Login sessions table for 2FA tracking
    c.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    otp_verified INTEGER DEFAULT 0
                )""")
    
    conn.commit()
    conn.close()

def hash_password(password):
    return sha256(password.encode()).hexdigest()

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_session_id():
    return secrets.token_urlsafe(32)

def generate_totp_secret():
    """Generate a new TOTP secret for Google Authenticator"""
    return pyotp.random_base32()

def generate_qr_code(username, secret):
    """Generate QR code for Google Authenticator"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="E2EE Secure Chat"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return img_str

def verify_totp(secret, token):
    """Verify TOTP token from Google Authenticator"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)

def send_email_otp(email, otp, otp_type="signup"):
    """Send OTP via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        
        if otp_type == "2fa":
            msg['Subject'] = "Your E2EE Chat Login Code (2FA)"
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>🔐 Two-Factor Authentication</h2>
                <p>Your login verification code is:</p>
                <h1 style="color: #667eea; letter-spacing: 5px;">{otp}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p><strong>If you didn't attempt to login, please secure your account immediately.</strong></p>
            </body>
            </html>
            """
        else:
            msg['Subject'] = "Your E2EE Chat Verification Code"
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>📧 Email Verification</h2>
                <p>Your verification code is:</p>
                <h1 style="color: #667eea; letter-spacing: 5px;">{otp}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request this code, please ignore this email.</p>
            </body>
            </html>
            """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_sms_otp(phone, otp, otp_type="signup"):
    """Send OTP via SMS using Twilio"""
    try:
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
        print(f"SMS error: {e}")
        return False

@app.route('/')
def home():
    return "🔐 E2EE Secure Chat Server Running (with 2FA: Email/SMS/TOTP)"

# --- REQUEST OTP (for signup) ---
@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.json
    username = data.get("username")
    contact = data.get("contact")
    
    if not username or not contact:
        return jsonify({"status": "error", "message": "Missing fields"}), 400
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check if username already exists
    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    
    # Check if contact already exists
    c.execute("SELECT username FROM users WHERE contact = ?", (contact,))
    existing_user = c.fetchone()
    if existing_user:
        conn.close()
        return jsonify({"status": "error", "message": "This email/phone is already registered"}), 409
    
    # Generate OTP
    otp = generate_otp()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Store OTP
    c.execute("INSERT OR REPLACE INTO otps (username, contact, otp, otp_type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
              (username, contact, otp, "signup", created_at, expires_at))
    conn.commit()
    conn.close()
    
    # Send OTP
    is_email = '@' in contact
    success = False
    
    if is_email:
        if EMAIL_USER and EMAIL_PASSWORD:
            success = send_email_otp(contact, otp, "signup")
        else:
            print(f"📧 OTP for {username}: {otp}")
            success = True
    else:
        if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
            success = send_sms_otp(contact, otp, "signup")
        else:
            print(f"📱 OTP for {username}: {otp}")
            success = True
    
    if success:
        return jsonify({"status": "success", "message": "OTP sent"})
    else:
        return jsonify({"status": "error", "message": "Failed to send OTP"}), 500

# --- VERIFY OTP ---
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    username = data.get("username")
    otp = data.get("otp")
    session_id = data.get("session_id")  # For 2FA
    
    if not username or not otp:
        return jsonify({"status": "error", "message": "Missing fields"}), 400
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT otp, expires_at, otp_type FROM otps WHERE username = ?", (username,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"status": "error", "message": "OTP not found"}), 404
    
    stored_otp, expires_at, otp_type = result
    
    # Check if OTP expired
    if datetime.now() > datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
        c.execute("DELETE FROM otps WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return jsonify({"status": "error", "message": "OTP expired"}), 400
    
    # Verify OTP
    if stored_otp == otp:
        # If this is a 2FA verification, mark the session as verified
        if otp_type == "2fa" and session_id:
            c.execute("UPDATE login_sessions SET otp_verified = 1 WHERE session_id = ? AND username = ?",
                     (session_id, username))
            conn.commit()
        
        conn.close()
        return jsonify({"status": "success", "message": "OTP verified"})
    else:
        conn.close()
        return jsonify({"status": "error", "message": "Invalid OTP"}), 401

# --- SETUP TOTP (Google Authenticator) ---
@app.route('/setup-totp', methods=['POST'])
def setup_totp():
    data = request.json
    username = data.get("username")
    
    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400
    
    # Generate TOTP secret
    secret = generate_totp_secret()
    qr_code = generate_qr_code(username, secret)
    
    return jsonify({
        "status": "success",
        "secret": secret,
        "qr_code": qr_code,
        "manual_entry": secret
    })

# --- SIGNUP ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    contact = data.get("contact")
    public_key = data.get("public_key")
    enable_2fa = data.get("enable_2fa", False)
    two_fa_method = data.get("two_fa_method")  # "email", "sms", or "totp"
    totp_secret = data.get("totp_secret")  # Only if method is "totp"

    if not username or not password or not contact or not public_key:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    if enable_2fa and not two_fa_method:
        return jsonify({"status": "error", "message": "2FA method required"}), 400

    if enable_2fa and two_fa_method == "totp" and not totp_secret:
        return jsonify({"status": "error", "message": "TOTP secret required"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Verify OTP was validated
    c.execute("SELECT username FROM otps WHERE username = ? AND otp_type = 'signup'", (username,))
    if not c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "OTP not verified"}), 401
    
    # Double-check contact uniqueness
    c.execute("SELECT username FROM users WHERE contact = ?", (contact,))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "This email/phone is already registered"}), 409
    
    try:
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""INSERT INTO users 
                     (username, password_hash, contact, public_key, two_fa_enabled, two_fa_method, totp_secret, created_at) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", 
                  (username, hash_password(password), contact, public_key, 
                   1 if enable_2fa else 0, two_fa_method if enable_2fa else None, 
                   totp_secret if enable_2fa and two_fa_method == "totp" else None, created_at))
        
        # Delete OTP after successful signup
        c.execute("DELETE FROM otps WHERE username = ?", (username,))
        
        conn.commit()
        return jsonify({
            "status": "success", 
            "message": "Signup successful",
            "two_fa_enabled": enable_2fa,
            "two_fa_method": two_fa_method if enable_2fa else None
        })
    except sqlite3.IntegrityError as e:
        conn.close()
        if "username" in str(e):
            return jsonify({"status": "error", "message": "Username already exists"}), 409
        elif "contact" in str(e):
            return jsonify({"status": "error", "message": "This email/phone is already registered"}), 409
        else:
            return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        conn.close()

# --- LOGIN (with 2FA) ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password_hash, two_fa_enabled, two_fa_method, contact, totp_secret FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    
    password_hash, two_fa_enabled, two_fa_method, contact, totp_secret = result
    
    if password_hash != hash_password(password):
        conn.close()
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    
    # If 2FA is not enabled, login directly
    if not two_fa_enabled:
        conn.close()
        return jsonify({
            "status": "success", 
            "message": "Login successful",
            "two_fa_required": False
        })
    
    # Create session for 2FA
    session_id = generate_session_id()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute("INSERT INTO login_sessions (session_id, username, created_at, expires_at, otp_verified) VALUES (?, ?, ?, ?, ?)",
              (session_id, username, created_at, expires_at, 0))
    conn.commit()
    
    # If TOTP (Google Authenticator), no need to send anything
    if two_fa_method == "totp":
        conn.close()
        return jsonify({
            "status": "success",
            "message": "Enter code from Google Authenticator",
            "two_fa_required": True,
            "two_fa_method": "totp",
            "session_id": session_id
        })
    
    # For email/SMS, generate and send OTP
    otp = generate_otp()
    c.execute("INSERT OR REPLACE INTO otps (username, contact, otp, otp_type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
              (username, contact, otp, "2fa", created_at, expires_at))
    conn.commit()
    conn.close()
    
    # Send OTP based on method
    success = False
    if two_fa_method == "email":
        if EMAIL_USER and EMAIL_PASSWORD:
            success = send_email_otp(contact, otp, "2fa")
        else:
            print(f"🔐 2FA OTP for {username}: {otp}")
            success = True
    elif two_fa_method == "sms":
        if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
            success = send_sms_otp(contact, otp, "2fa")
        else:
            print(f"🔐 2FA OTP for {username}: {otp}")
            success = True
    
    if success:
        masked_contact = contact if '@' in contact else contact[:3] + "****" + contact[-4:]
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

# --- VERIFY 2FA LOGIN ---
@app.route('/verify-2fa-login', methods=['POST'])
def verify_2fa_login():
    data = request.json
    session_id = data.get("session_id")
    username = data.get("username")
    code = data.get("code")
    
    if not session_id or not username or not code:
        return jsonify({"status": "error", "message": "Missing fields"}), 400
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Get user's 2FA method
    c.execute("SELECT two_fa_method, totp_secret FROM users WHERE username = ?", (username,))
    user_result = c.fetchone()
    
    if not user_result:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    two_fa_method, totp_secret = user_result
    
    # Verify based on method
    if two_fa_method == "totp":
        # Verify TOTP token
        if not verify_totp(totp_secret, code):
            conn.close()
            return jsonify({"status": "error", "message": "Invalid code"}), 401
    else:
        # Verify email/SMS OTP
        c.execute("SELECT otp, expires_at FROM otps WHERE username = ? AND otp_type = '2fa'", (username,))
        otp_result = c.fetchone()
        
        if not otp_result:
            conn.close()
            return jsonify({"status": "error", "message": "OTP not found"}), 404
        
        stored_otp, expires_at = otp_result
        
        # Check if OTP expired
        if datetime.now() > datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
            c.execute("DELETE FROM otps WHERE username = ?", (username,))
            c.execute("DELETE FROM login_sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            conn.close()
            return jsonify({"status": "error", "message": "OTP expired"}), 400
        
        # Verify OTP matches
        if stored_otp != code:
            conn.close()
            return jsonify({"status": "error", "message": "Invalid OTP"}), 401
        
        # Delete used OTP
        c.execute("DELETE FROM otps WHERE username = ? AND otp_type = '2fa'", (username,))
    
    # Mark session as verified
    c.execute("UPDATE login_sessions SET otp_verified = 1 WHERE session_id = ? AND username = ?",
             (session_id, username))
    
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "Login successful"})

# --- TOGGLE 2FA ---
@app.route('/toggle-2fa', methods=['POST'])
def toggle_2fa():
    data = request.json
    username = data.get("username")
    enable = data.get("enable", True)
    method = data.get("method")  # "email", "sms", or "totp"
    totp_secret = data.get("totp_secret")
    
    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400
    
    if enable and not method:
        return jsonify({"status": "error", "message": "2FA method required"}), 400
    
    if enable and method == "totp" and not totp_secret:
        return jsonify({"status": "error", "message": "TOTP secret required"}), 400
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    if enable:
        c.execute("UPDATE users SET two_fa_enabled = 1, two_fa_method = ?, totp_secret = ? WHERE username = ?", 
                 (method, totp_secret if method == "totp" else None, username))
    else:
        c.execute("UPDATE users SET two_fa_enabled = 0, two_fa_method = NULL, totp_secret = NULL WHERE username = ?", 
                 (username,))
    
    if c.rowcount == 0:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "status": "success", 
        "message": f"2FA {'enabled' if enable else 'disabled'}",
        "two_fa_enabled": enable,
        "two_fa_method": method if enable else None
    })

# --- GET PUBLIC KEY ---
@app.route('/public-key/<username>', methods=['GET'])
def get_public_key(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        return jsonify({"status": "success", "public_key": result[0]})
    else:
        return jsonify({"status": "error", "message": "User not found"}), 404

# --- SEND MESSAGE ---
@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    encrypted_message = data.get("encrypted_message")

    if not sender or not receiver or not encrypted_message:
        return jsonify({"status": "error", "message": "Missing data"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?", (receiver,))
    if not c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Receiver not found"}), 404

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute("INSERT INTO messages (sender, receiver, encrypted_message, timestamp) VALUES (?, ?, ?, ?)",
              (sender, receiver, encrypted_message, timestamp))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "Message sent"})

# --- GET MESSAGES ---
@app.route('/messages', methods=['GET'])
def get_messages():
    user1 = request.args.get("user1")
    user2 = request.args.get("user2")
    
    if not user1 or not user2:
        return jsonify({"status": "error", "message": "Missing users"}), 400
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""SELECT sender, receiver, encrypted_message, timestamp FROM messages 
                 WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                 ORDER BY id ASC""", (user1, user2, user2, user1))
    rows = c.fetchall()
    conn.close()
    
    messages = []
    for row in rows:
        messages.append({
            "sender": row[0],
            "receiver": row[1],
            "encrypted_message": row[2],
            "timestamp": row[3]
        })
    
    return jsonify({"messages": messages})

# --- GET USER LIST ---
@app.route('/users', methods=['GET'])
def get_users():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify({"users": users})

# --- CLEANUP EXPIRED SESSIONS (Background task) ---
def cleanup_expired_data():
    """Remove expired OTPs and sessions"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute("DELETE FROM otps WHERE expires_at < ?", (current_time,))
    c.execute("DELETE FROM login_sessions WHERE expires_at < ?", (current_time,))
    
    conn.commit()
    conn.close()

# --- Main ---

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)