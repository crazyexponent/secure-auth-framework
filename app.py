from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import subprocess
import sqlite3
import os
from module1_mfa.mfa_module import TOTPAuthenticator
from module2_password.password_manager import PasswordHashEngine
from module3_session.session_manager import PrivilegeLevelValidator

app = Flask(__name__)
app.secret_key = os.urandom(24) # Required for Flask session

# --- Database Setup ---
DB_PATH = 'users.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )
    ''')
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()
hasher = PasswordHashEngine(cost_factor=12)
priv_validator = PrivilegeLevelValidator()

def seed_admin():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username='admin'")
    if not cursor.fetchone():
        hashed_pw = hasher.hash_password("admin123")
        auth = TOTPAuthenticator("admin")
        cursor.execute("INSERT INTO users (username, password_hash, totp_secret, role) VALUES (?, ?, ?, ?)", 
                       ("admin", hashed_pw, auth.secret, "admin"))
    conn.commit()
    conn.close()

seed_admin()

# --- Routes ---

@app.route("/")
def home():
    if session.get('mfa_verified'):
        return redirect(url_for('dashboard'))
    return render_template("login.html")

@app.route("/signup", methods=["GET"])
def signup_page():
    return render_template("signup.html")

@app.route("/otp")
def otp():
    if not session.get('pre_auth_user'):
        return redirect(url_for('home'))
    return render_template("otp.html")

@app.route("/dashboard")
def dashboard():
    if not session.get('mfa_verified'):
        return redirect(url_for('home'))
    username = session.get('pre_auth_user', 'Unknown')
    role = session.get('role', 'user')
    return render_template("dashboard.html", username=username, role=role)

# --- API Routes ---

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "User already exists"}), 400
        
    # Generate password hash and TOTP secret
    hashed_pw = hasher.hash_password(password)
    auth = TOTPAuthenticator(username)
    secret = auth.secret
    
    cursor.execute("INSERT INTO users (username, password_hash, totp_secret, role) VALUES (?, ?, ?, ?)", 
                   (username, hashed_pw, secret, role))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT password_hash, failed_attempts, locked_until, role FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
    except sqlite3.OperationalError:
        cursor.execute("SELECT password_hash, failed_attempts, locked_until FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            row = (*row, 'user')
    
    if not row:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401

    password_hash, failed_attempts, locked_until, role = row
    failed_attempts = failed_attempts or 0

    from datetime import datetime, timedelta

    if locked_until:
        locked_time = datetime.fromisoformat(locked_until)
        if datetime.now() < locked_time:
            conn.close()
            remaining_time = max(1, int((locked_time - datetime.now()).total_seconds() / 60))
            return jsonify({"error": f"Account locked. Try again in {remaining_time} minutes."}), 403
        else:
            cursor.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
            conn.commit()
            failed_attempts = 0

    if hasher.verify_password(password, password_hash):
        cursor.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
        conn.commit()
        conn.close()
        session['pre_auth_user'] = username
        session['role'] = role
        return jsonify({"success": True})
    else:
        failed_attempts += 1
        if failed_attempts >= 3:
            lock_time = datetime.now() + timedelta(minutes=15)
            cursor.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?", (failed_attempts, lock_time.isoformat(), username))
            conn.commit()
            conn.close()
            return jsonify({"error": "Account locked due to 3 failed attempts. Try again in 15 minutes."}), 403
        else:
            cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempts, username))
            conn.commit()
            conn.close()
            return jsonify({"error": f"Invalid password. {3 - failed_attempts} attempts remaining."}), 401

@app.route("/api/verify_otp", methods=["POST"])
def api_verify_otp():
    username = session.get('pre_auth_user')
    if not username:
        return jsonify({"error": "No pre-authenticated session"}), 401
        
    data = request.json
    user_otp = data.get('otp')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "User not found"}), 404
        
    # Verify OTP
    auth = TOTPAuthenticator(username)
    auth.secret = row[0] # Inject the user's secret
    # Because TOTPAuthenticator creates the TOTP object in __init__, we need to recreate it or update it
    import pyotp
    auth.totp = pyotp.TOTP(auth.secret)
    
    if auth.verify_otp(user_otp):
        session['mfa_verified'] = True
        return jsonify({"success": True})
        
    return jsonify({"error": "Invalid OTP"}), 401

@app.route("/api/current_otp", methods=["GET"])
def api_current_otp():
    # Only for demonstration/simulator purposes
    username = session.get('pre_auth_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "User not found"}), 404
        
    auth = TOTPAuthenticator(username)
    auth.secret = row[0]
    import pyotp
    auth.totp = pyotp.TOTP(auth.secret)
    
    return jsonify({
        "otp": auth.generate_otp(),
        "secret": auth.secret
    })

# --- Runner Routes ---
@app.route("/run-full")
def run_full():
    user_role = session.get('role', 'user')
    if not priv_validator.can_access(user_role, 'admin'):
        return jsonify({"output": f"[DENIED] Privilege level '{user_role}' cannot access 'admin' resource.\nSecurity event logged. Escalation attempt blocked."})
        
    result = subprocess.run(
        ["python3", "main_runner.py"],
        capture_output=True, text=True
    )
    return jsonify({"output": result.stdout})

@app.route("/run-mfa")
def run_mfa():
    result = subprocess.run(
        ["python3", "module1_mfa/mfa_module.py"],
        capture_output=True, text=True
    )
    return jsonify({"output": result.stdout})

@app.route("/run-password")
def run_password():
    result = subprocess.run(
        ["python3", "module2_password/password_manager.py"],
        capture_output=True, text=True
    )
    return jsonify({"output": result.stdout})

@app.route("/run-session")
def run_session():
    user_role = session.get('role', 'user')
    if not priv_validator.can_access(user_role, 'admin'):
        return jsonify({"output": f"[DENIED] Privilege level '{user_role}' cannot access 'admin' resource.\nSecurity event logged. Escalation attempt blocked."})
        
    result = subprocess.run(
        ["python3", "module3_session/session_manager.py"],
        capture_output=True, text=True
    )
    return jsonify({"output": result.stdout})

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True, port=5001)