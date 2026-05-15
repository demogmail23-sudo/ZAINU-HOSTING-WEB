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
import shutil
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response
from flask_cors import CORS

# ============== CONFIGURATION ==============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
CORS(app, supports_credentials=True)

# Main account (Admin)
ADMIN_USERNAME = "ZAINU121"
ADMIN_PASSWORD = "8057558009"
USERS_FILE = os.path.join(BASE_DIR, "users.json")
REMEMBER_TOKENS_FILE = os.path.join(BASE_DIR, "remember_tokens.json")

# ============== HELPER FUNCTIONS ==============
def init_users_db():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            admin_data = {
                ADMIN_USERNAME: {
                    "password": hash_password(ADMIN_PASSWORD),
                    "created_at": datetime.now().isoformat(),
                    "last_login": None,
                    "is_admin": True
                }
            }
            json.dump(admin_data, f, indent=2)

def init_tokens_db():
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_remember_token(username):
    init_tokens_db()
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    
    tokens[token] = {
        "username": username,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires
    }
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    return token

def validate_remember_token(token):
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return None
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    if token not in tokens:
        return None
    token_data = tokens[token]
    expires_at = datetime.fromisoformat(token_data["expires_at"])
    if datetime.now() > expires_at:
        del tokens[token]
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return None
    return token_data["username"]

def register_user(username, password, created_by_admin=False):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username in users:
        return False, "User already exists"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    users[username] = {
        "password": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "is_admin": False,
        "created_by_admin": created_by_admin
    }
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)
    
    return True, "Account created successfully"

def authenticate_user(username, password):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username not in users:
        return False, "User not found"
    
    if users[username]["password"] != hash_password(password):
        return False, "Incorrect password"
    
    users[username]["last_login"] = datetime.now().isoformat()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    return True, "Login successful"

def is_admin(username):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    if username in users:
        return users[username].get("is_admin", False)
    return False

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
        if not is_admin(session['username']):
            return jsonify({"success": False, "message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ============== ROUTES ==============
@app.before_request
def check_remember_token():
    if 'username' in session:
        return
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        username = validate_remember_token(remember_token)
        if username:
            session['username'] = username

@app.route("/")
def home():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if is_admin(session['username']):
        return send_from_directory(BASE_DIR, "admin_panel.html")
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login")
def login_page():
    if 'username' in session:
        return redirect(url_for('home'))
    return send_from_directory(BASE_DIR, "login.html")

@app.route("/api/current_user")
def api_current_user():
    if 'username' in session:
        return jsonify({
            "success": True,
            "username": session['username'],
            "is_admin": is_admin(session['username'])
        })
    return jsonify({"success": False})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    remember_me = data.get("remember_me", False)
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"})
    
    success, message = authenticate_user(username, password)
    if success:
        session['username'] = username
        response_data = {"success": True, "message": message, "is_admin": is_admin(username)}
        
        if remember_me:
            token = create_remember_token(username)
            response = make_response(jsonify(response_data))
            response.set_cookie('remember_token', token, max_age=30*24*60*60, httponly=True)
            return response
        return jsonify(response_data)
    
    return jsonify({"success": False, "message": message})

@app.route("/api/logout", methods=["POST"])
def api_logout():
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
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"})
    
    success, message = register_user(username, password, created_by_admin=True)
    return jsonify({"success": success, "message": message})

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_all_users():
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    user_list = []
    for username, data in users.items():
        if username != ADMIN_USERNAME:
            user_list.append({
                "username": username,
                "created_at": data.get("created_at"),
                "last_login": data.get("last_login")
            })
    
    return jsonify({"success": True, "users": user_list})

@app.route("/api/admin/delete-user", methods=["POST"])
@admin_required
def delete_user():
    data = request.get_json()
    username_to_delete = data.get("username", "").strip()
    
    if not username_to_delete or username_to_delete == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "Cannot delete this user"})
    
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username_to_delete not in users:
        return jsonify({"success": False, "message": "User not found"})
    
    del users[username_to_delete]
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    user_dir = os.path.join(USERS_DIR, username_to_delete)
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
    
    return jsonify({"success": True, "message": "User deleted successfully"})

# ============== SERVER MANAGEMENT ROUTES ==============
def get_user_servers_dir():
    return os.path.join(USERS_DIR, session['username'], "SERVERS")

def sanitize_folder_name(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

running_procs = {}

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
                servers.append({
                    "id": len(servers) + 1,
                    "title": folder,
                    "folder": folder,
                    "subtitle": "Python Server"
                })
    return jsonify({"success": True, "servers": servers})

@app.route("/add", methods=["POST"])
@login_required
def add_server():
    data = request.get_json()
    name = data.get("name", "").strip()
    folder = sanitize_folder_name(name)
    user_servers_dir = get_user_servers_dir()
    target = os.path.join(user_servers_dir, folder)
    
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"}), 409
    
    os.makedirs(target)
    return jsonify({"success": True})

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
            if p.is_running():
                running = True
                cpu = f"{p.cpu_percent(interval=0.1)}%"
                mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
        except:
            pass
    
    user_servers_dir = get_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    logs = ""
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors='ignore') as f:
                logs = f.read()[-5000:]
        except:
            pass
    
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
        return jsonify({"success": True})
    
    user_servers_dir = get_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    
    # Find startup file
    startup_file = None
    server_path = os.path.join(user_servers_dir, folder)
    for file in os.listdir(server_path):
        if file.endswith(('.py', '.js', '.html')):
            startup_file = file
            break
    
    if not startup_file:
        return jsonify({"success": False, "message": "No startup file found"})
    
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"\n[SYSTEM] Starting {startup_file} at {datetime.now()}\n")
    
    log_file_obj = open(log_path, "a", encoding="utf-8")
    
    if startup_file.endswith('.py'):
        proc = subprocess.Popen(
            [sys.executable, "-u", startup_file],
            cwd=server_path,
            stdout=log_file_obj,
            stderr=log_file_obj
        )
    else:
        proc = subprocess.Popen(
            ["python", "-m", "http.server", "8000"],
            cwd=server_path,
            stdout=log_file_obj,
            stderr=log_file_obj
        )
    
    running_procs[proc_key] = proc
    return jsonify({"success": True})

@app.route("/server/set-startup/<folder>", methods=["POST"])
@login_required
def set_startup(folder):
    return jsonify({"success": True})

# ============== FILE MANAGEMENT ROUTES ==============
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
            results.append({"name": safe_name})
    
    return jsonify({"success": True, "uploaded_files": results})

@app.route("/files/delete/<folder>", methods=["POST"])
@login_required
def delete_file(folder):
    user_servers_dir = get_user_servers_dir()
    data = request.get_json()
    file_path = os.path.join(user_servers_dir, folder, data['name'])
    os.remove(file_path)
    return jsonify({"success": True})

@app.route("/files/rename/<folder>", methods=["POST"])
@login_required
def rename_file(folder):
    user_servers_dir = get_user_servers_dir()
    data = request.get_json()
    old_path = os.path.join(user_servers_dir, folder, data['old'])
    new_path = os.path.join(user_servers_dir, folder, data['new'])
    os.rename(old_path, new_path)
    return jsonify({"success": True})

@app.route("/files/install/<folder>", methods=["POST"])
@login_required
def install_req(folder):
    user_servers_dir = get_user_servers_dir()
    req_path = os.path.join(user_servers_dir, folder, "requirements.txt")
    if not os.path.exists(req_path):
        return jsonify({"success": False, "message": "requirements.txt not found"})
    
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    proc = subprocess.Popen(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        cwd=os.path.join(user_servers_dir, folder),
        stdout=open(log_path, "a"),
        stderr=open(log_path, "a")
    )
    return jsonify({"success": True, "message": "Installation started"})

# ============== RUN SERVER ==============
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
