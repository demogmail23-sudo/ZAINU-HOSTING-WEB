# app.py - UPDATED WITH ALL FEATURES + GOOGLE LOGIN

import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import time
import sqlite3
import threading
import shutil
import csv
import io
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response
from flask_cors import CORS
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
import requests

# ============== CONFIGURATION ==============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
DATABASE_PATH = os.path.join(BASE_DIR, "zainu_host.db")
BACKUP_DIR = os.path.join(BASE_DIR, "BACKUPS")
LOGS_DIR = os.path.join(BASE_DIR, "LOGS")

# Create directories
for dir_path in [USERS_DIR, BACKUP_DIR, LOGS_DIR]:
    os.makedirs(dir_path, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
CORS(app, supports_credentials=True)

# ============== GOOGLE OAUTH CONFIGURATION ==============
# IMPORTANT: Replace with your own Google OAuth credentials
# Get from: https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID = "525604391861-gu4m8u06cp5ocj7hu9eb07lfkf6tpcgb.ap-ps.googleapis.com"
GOOGLE_CLIENT_SECRET = "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"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# ============== EMAIL CONFIGURATION ==============
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME", "")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD", "")
mail = Mail(app)

# ============== DATABASE SETUP ==============
def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password_hash TEXT,
        google_id TEXT UNIQUE,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        storage_quota INTEGER DEFAULT 500,
        storage_used INTEGER DEFAULT 0,
        created_at TEXT,
        last_login TEXT,
        theme TEXT DEFAULT 'dark',
        twofa_secret TEXT,
        twofa_enabled INTEGER DEFAULT 0
    )''')
    
    # Activity logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        details TEXT,
        ip_address TEXT,
        timestamp TEXT
    )''')
    
    # Servers table
    c.execute('''CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT,
        server_name TEXT,
        folder_name TEXT,
        custom_domain TEXT,
        server_type TEXT DEFAULT 'python',
        env_vars TEXT,
        created_at TEXT,
        last_deployed TEXT,
        is_running INTEGER DEFAULT 0,
        port INTEGER
    )''')
    
    # Deployments table
    c.execute('''CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER,
        version TEXT,
        status TEXT,
        logs TEXT,
        deployed_at TEXT
    )''')
    
    # Backups table
    c.execute('''CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        backup_name TEXT,
        backup_path TEXT,
        size INTEGER,
        created_at TEXT
    )''')
    
    # Cron jobs table
    c.execute('''CREATE TABLE IF NOT EXISTS cron_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        server_id INTEGER,
        schedule TEXT,
        command TEXT,
        is_active INTEGER DEFAULT 1,
        last_run TEXT,
        next_run TEXT
    )''')
    
    # API keys table
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        api_key TEXT UNIQUE,
        name TEXT,
        created_at TEXT,
        last_used TEXT,
        is_active INTEGER DEFAULT 1
    )''')
    
    # Team members table
    c.execute('''CREATE TABLE IF NOT EXISTS team_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT,
        member_email TEXT,
        member_username TEXT,
        role TEXT DEFAULT 'viewer',
        server_access TEXT,
        invited_at TEXT,
        accepted_at TEXT
    )''')
    
    # Rate limiting table
    c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT,
        action TEXT,
        count INTEGER DEFAULT 1,
        reset_at TEXT
    )''')
    
    conn.commit()
    
    # Create admin user if not exists
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@zainu.com")
    c.execute("SELECT * FROM users WHERE username = ?", ("ZAINU121",))
    if not c.fetchone():
        c.execute('''INSERT INTO users (username, email, password_hash, is_admin, created_at)
                     VALUES (?, ?, ?, ?, ?)''',
                  ("ZAINU121", admin_email, hashlib.sha256("8057558009".encode()).hexdigest(), 1, datetime.now().isoformat()))
        conn.commit()
    
    conn.close()

init_database()

# ============== HELPER FUNCTIONS ==============
def log_activity(username, action, details="", ip=None):
    """Log user activity"""
    if ip is None and request:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO activity_logs (username, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
              (username, action, details, ip, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_google_id(google_id):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
    user = c.fetchone()
    conn.close()
    return user

def create_or_update_google_user(google_user):
    """Create or update user from Google login"""
    email = google_user.get('email')
    name = google_user.get('name', email.split('@')[0])
    google_id = google_user.get('id')
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    existing = get_user_by_email(email)
    
    if existing:
        # Update existing user with Google ID if not set
        c.execute("UPDATE users SET google_id = ?, last_login = ? WHERE email = ?",
                  (google_id, datetime.now().isoformat(), email))
        username = existing[1]
    else:
        # Create new user
        username = name.replace(" ", "_").lower()
        # Ensure unique username
        base_username = username
        counter = 1
        while True:
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            if not c.fetchone():
                break
            username = f"{base_username}{counter}"
            counter += 1
        
        c.execute('''INSERT INTO users (username, email, google_id, is_admin, created_at, last_login)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (username, email, google_id, 0, datetime.now().isoformat(), datetime.now().isoformat()))
        conn.commit()
        
        # Create user directory
        user_dir = os.path.join(USERS_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)
        
        log_activity(username, "google_signup", f"New user signed up with Google")
    
    conn.close()
    return username

def send_email_notification(to_email, subject, body):
    """Send email notification"""
    try:
        if app.config['MAIL_USERNAME']:
            msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to_email])
            msg.body = body
            mail.send(msg)
            return True
    except Exception as e:
        print(f"Email error: {e}")
    return False

def check_rate_limit(identifier, action, limit=100, window=3600):
    """Check rate limit for an action"""
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    reset_at = (datetime.now() + timedelta(seconds=window)).isoformat()
    
    c.execute("SELECT * FROM rate_limits WHERE identifier = ? AND action = ?", (identifier, action))
    record = c.fetchone()
    
    if record:
        if datetime.fromisoformat(record[5]) > datetime.now():
            if record[4] >= limit:
                conn.close()
                return False
            c.execute("UPDATE rate_limits SET count = count + 1 WHERE id = ?", (record[0],))
        else:
            c.execute("UPDATE rate_limits SET count = 1, reset_at = ? WHERE id = ?", (reset_at, record[0]))
    else:
        c.execute("INSERT INTO rate_limits (identifier, action, count, reset_at) VALUES (?, ?, ?, ?)",
                  (identifier, action, 1, reset_at))
    
    conn.commit()
    conn.close()
    return True

def create_backup(username):
    """Create backup of user data"""
    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        return None
    
    backup_name = f"{username}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    shutil.make_archive(backup_path.replace('.zip', ''), 'zip', user_dir)
    
    size = os.path.getsize(backup_path)
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO backups (username, backup_name, backup_path, size, created_at) VALUES (?, ?, ?, ?, ?)",
              (username, backup_name, backup_path, size, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    return backup_name

def restore_backup(username, backup_name):
    """Restore user from backup"""
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT backup_path FROM backups WHERE username = ? AND backup_name = ?", (username, backup_name))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return False
    
    backup_path = result[0]
    user_dir = os.path.join(USERS_DIR, username)
    
    # Remove current data
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
    
    # Extract backup
    shutil.unpack_archive(backup_path, os.path.dirname(user_dir), 'zip')
    
    return True

# ============== DECORATORS ==============
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE username = ?", (session['username'],))
        user = c.fetchone()
        conn.close()
        if not user or not user[0]:
            return jsonify({"success": False, "message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ============== GOOGLE AUTH ROUTES ==============
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def google_auth():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        
        username = create_or_update_google_user(user_info)
        session['username'] = username
        
        log_activity(username, "google_login", f"Logged in with Google", request.remote_addr)
        
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Google auth error: {e}")
        return redirect(url_for('login_page'))

# ============== ROUTES ==============
@app.route("/")
def home():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username = ?", (session['username'],))
    user = c.fetchone()
    conn.close()
    
    if user and user[0]:
        return send_from_directory(BASE_DIR, "admin_panel.html")
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login")
def login_page():
    if 'username' in session:
        return redirect(url_for('home'))
    return send_from_directory(BASE_DIR, "login.html")

# ============== API ROUTES ==============
@app.route("/api/current_user")
def api_current_user():
    if 'username' in session:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT is_admin, email FROM users WHERE username = ?", (session['username'],))
        user = c.fetchone()
        conn.close()
        
        return jsonify({
            "success": True,
            "username": session['username'],
            "is_admin": user[0] if user else False,
            "email": user[1] if user else None,
            "has_remember_token": bool(request.cookies.get('remember_token'))
        })
    return jsonify({"success": False})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    username = session.get('username')
    if username:
        log_activity(username, "logout", "User logged out", request.remote_addr)
    session.pop('username', None)
    response = make_response(jsonify({"success": True}))
    response.set_cookie('remember_token', '', expires=0)
    return response

@app.route("/api/register", methods=["POST"])
@admin_required
def api_register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    email = data.get("email", "").strip()
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"})
    
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"})
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"success": False, "message": "Username already exists"})
    
    if email:
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Email already exists"})
    
    c.execute('''INSERT INTO users (username, email, password_hash, is_admin, created_at)
                 VALUES (?, ?, ?, ?, ?)''',
              (username, email, hashlib.sha256(password.encode()).hexdigest(), 0, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    # Create user directory
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)
    
    log_activity(session['username'], "create_user", f"Created user: {username}", request.remote_addr)
    
    # Send email notification
    if email:
        send_email_notification(email, "Welcome to ZAINU HOST", 
                               f"Hello {username},\n\nYour account has been created successfully!\n\nUsername: {username}\n\nVisit: zainu.host\n\nRegards,\nZAINU HOST Team")
    
    return jsonify({"success": True, "message": "User created successfully"})

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_all_users():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT username, email, is_admin, is_active, created_at, last_login, storage_quota, storage_used FROM users WHERE username != 'ZAINU121'")
    users = c.fetchall()
    conn.close()
    
    user_list = []
    for user in users:
        user_list.append({
            "username": user[0],
            "email": user[1],
            "is_admin": bool(user[2]),
            "is_active": bool(user[3]),
            "created_at": user[4],
            "last_login": user[5],
            "storage_quota": user[6],
            "storage_used": user[7]
        })
    
    return jsonify({"success": True, "users": user_list})

@app.route("/api/admin/delete-user", methods=["POST"])
@admin_required
def delete_user_admin():
    data = request.get_json()
    username = data.get("username", "").strip()
    
    if username == "ZAINU121":
        return jsonify({"success": False, "message": "Cannot delete main admin"})
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    c.execute("DELETE FROM activity_logs WHERE username = ?", (username,))
    c.execute("DELETE FROM servers WHERE owner = ?", (username,))
    c.execute("DELETE FROM backups WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    
    # Delete user directory
    user_dir = os.path.join(USERS_DIR, username)
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
    
    log_activity(session['username'], "delete_user", f"Deleted user: {username}", request.remote_addr)
    
    return jsonify({"success": True, "message": "User deleted successfully"})

@app.route("/api/admin/activity-logs", methods=["GET"])
@admin_required
def get_activity_logs():
    limit = request.args.get("limit", 100, type=int)
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT username, action, details, ip_address, timestamp FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,))
    logs = c.fetchall()
    conn.close()
    
    log_list = []
    for log in logs:
        log_list.append({
            "username": log[0],
            "action": log[1],
            "details": log[2],
            "ip": log[3],
            "timestamp": log[4]
        })
    
    return jsonify({"success": True, "logs": log_list})

@app.route("/api/admin/backup", methods=["POST"])
@admin_required
def create_full_backup():
    backup_name = f"full_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    # Backup database
    shutil.copy2(DATABASE_PATH, os.path.join(backup_path + "_db.sqlite"))
    
    # Backup USERS directory
    shutil.make_archive(backup_path + "_users", 'zip', USERS_DIR)
    
    log_activity(session['username'], "full_backup", f"Created full backup: {backup_name}", request.remote_addr)
    
    return jsonify({"success": True, "message": "Backup created", "backup_name": backup_name})

@app.route("/api/user/stats")
@login_required
def user_stats():
    username = session['username']
    user_dir = os.path.join(USERS_DIR, username)
    servers_dir = os.path.join(user_dir, "SERVERS")
    
    # Calculate storage used
    storage_used = 0
    if os.path.exists(user_dir):
        for root, dirs, files in os.walk(user_dir):
            for f in files:
                fp = os.path.join(root, f)
                storage_used += os.path.getsize(fp)
    storage_used_mb = storage_used // (1024 * 1024)
    
    # Count servers
    server_count = 0
    if os.path.exists(servers_dir):
        server_count = len([d for d in os.listdir(servers_dir) if os.path.isdir(os.path.join(servers_dir, d))])
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT storage_quota FROM users WHERE username = ?", (username,))
    quota = c.fetchone()
    conn.close()
    
    return jsonify({
        "success": True,
        "storage_used": storage_used_mb,
        "storage_quota": quota[0] if quota else 500,
        "server_count": server_count,
        "backup_count": len([f for f in os.listdir(BACKUP_DIR) if username in f])
    })

@app.route("/api/user/api-keys", methods=["GET", "POST"])
@login_required
def manage_api_keys():
    username = session['username']
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    if request.method == "GET":
        c.execute("SELECT api_key, name, created_at, last_used, is_active FROM api_keys WHERE username = ?", (username,))
        keys = c.fetchall()
        conn.close()
        
        return jsonify({
            "success": True,
            "api_keys": [{"key": k[0], "name": k[1], "created_at": k[2], "last_used": k[3], "is_active": bool(k[4])} for k in keys]
        })
    
    data = request.get_json()
    name = data.get("name", "Default Key")
    api_key = secrets.token_urlsafe(32)
    
    c.execute("INSERT INTO api_keys (username, api_key, name, created_at) VALUES (?, ?, ?, ?)",
              (username, api_key, name, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    log_activity(username, "create_api_key", f"Created API key: {name}", request.remote_addr)
    
    return jsonify({"success": True, "api_key": api_key})

@app.route("/api/user/backups", methods=["GET", "POST"])
@login_required
def user_backups():
    username = session['username']
    
    if request.method == "GET":
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("SELECT backup_name, size, created_at FROM backups WHERE username = ? ORDER BY id DESC", (username,))
        backups = c.fetchall()
        conn.close()
        
        return jsonify({
            "success": True,
            "backups": [{"name": b[0], "size": b[1], "created_at": b[2]} for b in backups]
        })
    
    # POST - Create backup
    backup_name = create_backup(username)
    if backup_name:
        return jsonify({"success": True, "backup_name": backup_name})
    return jsonify({"success": False, "message": "Backup failed"})

# ============== SERVER ROUTES (Existing ones + enhancements) ==============
def get_user_servers_dir():
    return os.path.join(USERS_DIR, session['username'], "SERVERS")

def sanitize_folder_name(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

@app.route("/servers")
@login_required
def get_servers():
    user_servers_dir = get_user_servers_dir()
    os.makedirs(user_servers_dir, exist_ok=True)
    
    servers = []
    if os.path.exists(user_servers_dir):
        for folder in os.listdir(user_servers_dir):
            folder_path = os.path.join(user_servers_dir, folder)
            if os.path.isdir(folder_path):
                # Get server info from database
                conn = sqlite3.connect(DATABASE_PATH)
                c = conn.cursor()
                c.execute("SELECT server_type, custom_domain, is_running FROM servers WHERE folder_name = ? AND owner = ?", 
                         (folder, session['username']))
                db_server = c.fetchone()
                conn.close()
                
                servers.append({
                    "id": len(servers) + 1,
                    "title": folder,
                    "folder": folder,
                    "subtitle": db_server[0] if db_server else "python",
                    "custom_domain": db_server[1] if db_server else None,
                    "is_running": bool(db_server[2]) if db_server else False
                })
    
    return jsonify({"success": True, "servers": servers})

@app.route("/add", methods=["POST"])
@login_required
def add_server():
    data = request.get_json()
    name = data.get("name", "").strip()
    server_type = data.get("type", "python")
    
    folder = sanitize_folder_name(name)
    user_servers_dir = get_user_servers_dir()
    target = os.path.join(user_servers_dir, folder)
    
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"}), 409
    
    os.makedirs(target)
    
    # Save to database
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO servers (owner, server_name, folder_name, server_type, created_at, port)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (session['username'], name, folder, server_type, datetime.now().isoformat(), 8000 + len(os.listdir(user_servers_dir))))
    conn.commit()
    conn.close()
    
    log_activity(session['username'], "create_server", f"Created server: {name}", request.remote_addr)
    
    return jsonify({"success": True, "servers": get_servers().json["servers"]})

# Running processes dictionary
running_procs = {}

@app.route("/server/stats/<folder>")
@login_required
def get_stats(folder):
    proc_key = f"{session['username']}_{folder}"
    proc = running_procs.get(proc_key)
    running = False
    cpu, mem = "0%", "0 MB"
    
    if proc and psutil.pid_exists(proc.pid):
        try:
            p = psutil.Process(proc.pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                running = True
                cpu = f"{p.cpu_percent(interval=0.1)}%"
                mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
        except:
            pass
    
    user_servers_dir = get_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    logs = ""
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors='ignore') as f:
            logs = f.read()[-5000:]  # Last 5000 chars
    
    return jsonify({
        "status": "Running" if running else "Offline",
        "cpu": cpu,
        "mem": mem,
        "logs": logs,
        "ip": socket.gethostbyname(socket.gethostname())
    })

@app.route("/server/action/<folder>/<act>", methods=["POST"])
@login_required
def server_action(folder, act):
    proc_key = f"{session['username']}_{folder}"
    
    # Stop existing process
    if proc_key in running_procs:
        try:
            p = psutil.Process(running_procs[proc_key].pid)
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
        except:
            pass
        del running_procs[proc_key]
    
    if act == "stop":
        log_activity(session['username'], "stop_server", f"Stopped server: {folder}", request.remote_addr)
        return jsonify({"success": True})
    
    # Start or restart
    user_servers_dir = get_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    
    # Find startup file
    startup_file = None
    for file in os.listdir(os.path.join(user_servers_dir, folder)):
        if file.endswith(('.py', '.js', '.html')):
            startup_file = file
            break
    
    if not startup_file:
        return jsonify({"success": False, "message": "No startup file found"})
    
    # Open log file
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"\n[SYSTEM] Starting {startup_file} at {datetime.now()}\n")
    
    log_file_obj = open(log_path, "a", encoding="utf-8")
    
    # Start process based on file type
    if startup_file.endswith('.py'):
        proc = subprocess.Popen(
            [sys.executable, "-u", startup_file],
            cwd=os.path.join(user_servers_dir, folder),
            stdout=log_file_obj,
            stderr=log_file_obj
        )
    elif startup_file.endswith('.js'):
        proc = subprocess.Popen(
            ["node", startup_file],
            cwd=os.path.join(user_servers_dir, folder),
            stdout=log_file_obj,
            stderr=log_file_obj
        )
    else:
        # For HTML, just serve it
        log_file_obj.close()
        return jsonify({"success": True, "message": "HTML file ready to serve"})
    
    running_procs[proc_key] = proc
    log_activity(session['username'], "start_server", f"Started server: {folder} with {startup_file}", request.remote_addr)
    
    return jsonify({"success": True})

# File management routes
@app.route("/files/list/<folder>")
@login_required
def list_files(folder):
    user_servers_dir = get_user_servers_dir()
    path = os.path.join(user_servers_dir, folder)
    files = []
    if os.path.exists(path):
        for f in os.listdir(path):
            if f in ["server.log"]:
                continue
            f_path = os.path.join(path, f)
            if os.path.isfile(f_path):
                files.append({"name": f, "size": f"{os.path.getsize(f_path) / 1024:.1f} KB"})
    return jsonify(files)

@app.route("/files/content/<folder>/<filename>")
@login_required
def get_file_content(folder, filename):
    user_servers_dir = get_user_servers_dir()
    file_path = os.path.join(user_servers_dir, folder, filename)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"content": f.read()})
    except:
        return jsonify({"content": ""})

@app.route("/files/save/<folder>/<filename>", methods=["POST"])
@login_required
def save_file_content(folder, filename):
    user_servers_dir = get_user_servers_dir()
    file_path = os.path.join(user_servers_dir, folder, filename)
    data = request.json
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(data.get('content', ''))
    log_activity(session['username'], "edit_file", f"Edited: {filename}", request.remote_addr)
    return jsonify({"success": True})

@app.route("/files/upload/<folder>", methods=["POST"])
@login_required
def upload_file(folder):
    user_servers_dir = get_user_servers_dir()
    uploaded_files = request.files.getlist('files[]')
    results = []
    
    for f in uploaded_files:
        if f and f.filename:
            safe_name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", f.filename)
            save_path = os.path.join(user_servers_dir, folder, safe_name)
            f.save(save_path)
            results.append({"name": safe_name, "size": f"{os.path.getsize(save_path) / 1024:.2f} KB"})
    
    log_activity(session['username'], "upload_files", f"Uploaded {len(results)} file(s) to {folder}", request.remote_addr)
    
    return jsonify({"success": True, "uploaded_files": results})

@app.route("/files/delete/<folder>", methods=["POST"])
@login_required
def delete_file(folder):
    user_servers_dir = get_user_servers_dir()
    data = request.get_json()
    file_path = os.path.join(user_servers_dir, folder, data['name'])
    os.remove(file_path)
    log_activity(session['username'], "delete_file", f"Deleted: {data['name']}", request.remote_addr)
    return jsonify({"success": True})

@app.route("/server/set-startup/<folder>", methods=["POST"])
@login_required
def set_startup(folder):
    # This just sets which file to run, but we auto-detect anyway
    return jsonify({"success": True})

# ============== CUSTOM DOMAIN ROUTES ==============
@app.route("/api/domain/set", methods=["POST"])
@login_required
def set_custom_domain():
    data = request.get_json()
    folder = data.get("folder")
    domain = data.get("domain", "").strip()
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("UPDATE servers SET custom_domain = ? WHERE folder_name = ? AND owner = ?", 
              (domain if domain else None, folder, session['username']))
    conn.commit()
    conn.close()
    
    log_activity(session['username'], "set_domain", f"Set domain {domain} for {folder}", request.remote_addr)
    
    return jsonify({"success": True, "message": "Domain updated"})

# ============== ENVIRONMENT VARIABLES ==============
@app.route("/api/env/<folder>", methods=["GET", "POST"])
@login_required
def manage_env_vars(folder):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    if request.method == "GET":
        c.execute("SELECT env_vars FROM servers WHERE folder_name = ? AND owner = ?", (folder, session['username']))
        result = c.fetchone()
        conn.close()
        
        env_vars = json.loads(result[0]) if result and result[0] else {}
        return jsonify({"success": True, "env_vars": env_vars})
    
    data = request.get_json()
    env_vars = json.dumps(data.get("env_vars", {}))
    c.execute("UPDATE servers SET env_vars = ? WHERE folder_name = ? AND owner = ?", 
              (env_vars, folder, session['username']))
    conn.commit()
    conn.close()
    
    log_activity(session['username'], "update_env", f"Updated env vars for {folder}", request.remote_addr)
    
    return jsonify({"success": True})

# ============== CRON JOBS ==============
@app.route("/api/cron", methods=["GET", "POST"])
@login_required
def manage_cron_jobs():
    username = session['username']
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    if request.method == "GET":
        c.execute("SELECT id, server_id, schedule, command, is_active, last_run, next_run FROM cron_jobs WHERE username = ?", (username,))
        jobs = c.fetchall()
        conn.close()
        
        return jsonify({
            "success": True,
            "cron_jobs": [{"id": j[0], "server_id": j[1], "schedule": j[2], "command": j[3], 
                          "is_active": bool(j[4]), "last_run": j[5], "next_run": j[6]} for j in jobs]
        })
    
    data = request.get_json()
    c.execute('''INSERT INTO cron_jobs (username, server_id, schedule, command, next_run, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (username, data.get("server_id"), data.get("schedule"), data.get("command"),
               (datetime.now() + timedelta(minutes=1)).isoformat(), datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

# ============== TEAM MANAGEMENT ==============
@app.route("/api/team/invite", methods=["POST"])
@login_required
def invite_team_member():
    data = request.get_json()
    email = data.get("email")
    role = data.get("role", "viewer")
    server_access = json.dumps(data.get("servers", []))
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO team_members (owner, member_email, role, server_access, invited_at)
                 VALUES (?, ?, ?, ?, ?)''',
              (session['username'], email, role, server_access, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    send_email_notification(email, "Team Invitation - ZAINU HOST", 
                           f"You've been invited to join {session['username']}'s team on ZAINU HOST")
    
    return jsonify({"success": True, "message": "Invitation sent"})

# ============== RUN SERVER ==============
if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 21910))
    app.run(host="0.0.0.0", port=port, debug=False)  # debug=False karna