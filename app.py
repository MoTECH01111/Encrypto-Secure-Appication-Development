# Morris Ouedraogo 05/12/2025 Secure application 
from flask import Flask, request, redirect, session, render_template, render_template_string, jsonify # Import flask tools for routing, session handling, html rendering and JSON
import sqlite3 # Import sqlite3 db
from datetime import datetime, timedelta # Import date/time
from argon2 import PasswordHasher # Import argon 2
import re  # Import Regex username validation
import os # Import managing OS files
import json # Import JSON
import base64 # Import encoding encrypted data 
import hashlib # Import Hash master key
import time # Import session timers
import logging # Import logging 
from logging.handlers import RotatingFileHandler # Import logging
import unicodedata # Import rotating logs for security and debug
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Import sanitize module usersname and messages
from flask_wtf.csrf import CSRFProtect, CSRFError # Import AES-GCM authenticated encryption
from werkzeug.exceptions import HTTPException # Import CSRF protection

DB_NAME = "secure.db" # Database

# logging setup 
LOG_DIR = "logs" # create logs dir
os.makedirs(LOG_DIR, exist_ok=True) # ensures logs dir exist

logger = logging.getLogger("encrypto_app") # Create a logger application
logger.setLevel(logging.INFO) # Logger INFO

if not logger.handlers:
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "app.log"),
        maxBytes=1_000_000,   # 1MB per file
        backupCount=5         # Keeps rotating log file
    )
    formatter = logging.Formatter( # All logins , lockouts, failed attempts, message sends, CSRF attacks, Exceptions
        "%(asctime)s [%(levelname)s] %(name)s %(message)s"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def get_client_ip() -> str: # IP detection for security logs
    """Return client IP for logging (no trust/security assumptions)."""
    try:
        return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    except RuntimeError:
        return "unknown" # Used to log , login attempts, message sends, errors

# Flask Secret key
SECRET_FILE = "secret.key"

def load_or_create_secret_key(): # This function creates secret key 
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            key = f.read()
            logger.info("Loaded existing Flask secret key from disk.")
            return key
    key = os.urandom(64)  # 512-bit secret
    with open(SECRET_FILE, "wb") as f:
        f.write(key)
    logger.warning("Generated new Flask secret key no keys were  found.")
    return key # Persists session signing key


app = Flask(__name__) # flask app initialisation
app.secret_key = load_or_create_secret_key()
app.config["WTF_CSRF_ENABLED"] = True # Enabled WTF_CSRF
app.config["WTF_CSRF_TIME_LIMIT"] = None # Enable time limit

csrf = CSRFProtect(app) # CSRF protection enabled

# Secure cookies & session config
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# Argon2id Hash
ph = PasswordHasher()

# Username regex after sanitization
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# Sanitize username 
def sanitize_username(username: str) -> str:
    """Remove invisible, control, and unsafe Unicode from usernames."""
    if not isinstance(username, str):
        return ""
    username = unicodedata.normalize("NFKC", username) # Unicode using NFKC to remove invisible characters

    cleaned = []
    for ch in username:
        category = unicodedata.category(ch) # Unicode category with c

        if category.startswith("C"):   # If the category starts with C
            continue
        if category == "Mn": # Detects non spacinf mark mn
            continue
        if ch.isspace(): # Detects all white space
            continue
        cleaned.append(ch)

    return "".join(cleaned)


def sanitize_message(text: str) -> str: 
    """Remove invisible control unicode attacks while allowing emojis."""
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKC", text) # Normalises text to NFKC

    cleaned = [] # 
    for ch in text:
        cat = unicodedata.category(ch) # All unicode control characters
        # Dangerous direction-override characters
        if cat.startswith("C"): 
            continue 
        if ch in ["\u202E", "\u202D", "\u202B", "\u2066", "\u2067"]: #Prevent text direction manipulation attacks and invisible injection attacks while still allowing emojis
            continue  
        cleaned.append(ch)

    return "".join(cleaned)


# AES-GCM Encryption Key
KEY_FILE = "key.json"

def load_or_create_key(): # This creates encryption key is for message encryptions
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            data = json.load(f)
            logger.info("Loaded existing AES master key metadata.")
            return data["MASTER_KEY"] 

    key_bytes = os.urandom(64)
    key_hex = key_bytes.hex()
    with open(KEY_FILE, "w") as f:
        json.dump({"MASTER_KEY": key_hex}, f, indent=4)
    logger.warning("Generated new AES master key no previous key file  was found.")
    return key_hex

MASTER_KEY_HEX = load_or_create_key() # 
AES_KEY = hashlib.sha256(bytes.fromhex(MASTER_KEY_HEX)).digest()
aesgcm = AESGCM(AES_KEY)


# Uses encryption to 
def encrypt_message(plaintext: str) -> str:
    plaintext = sanitize_message(plaintext) # Removes dangerous Unicode characters
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None) # AES-GCM requires a unique 12-byte nonce for every encryption
    return base64.urlsafe_b64encode(nonce + ct).decode() # Base64 encoding makes it safe for databases


def decrypt_message(token: str) -> str:
    try:
        data = base64.urlsafe_b64decode(token.encode()) # Converts back from base64 format to raw bytes
        nonce = data[:12] #  First 12 bytes are used the nonce used for encryption
        ct = data[12:] # Extract ciphertext
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode() # Protects against tampering and corruption
    except Exception: # Protects against crashes
        # Do not log token contents
        logger.error("Decryption error for stored message token.", exc_info=True)
        return "[DECRYPTION ERROR]"


# Db setup
def setup_db():
    conn = sqlite3.connect(DB_NAME) # Opens SQLite connection
    conn.row_factory = sqlite3.Row  # Enables dict like row access
    return conn


def init_db():
    conn = setup_db()
    c = conn.cursor()
    # Drops and recreates users and messages tables.
    c.execute("DROP TABLE IF EXISTS messages")
    c.execute("DROP TABLE IF EXISTS users")

    #Creates table
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            last_seen DATETIME,
            is_online INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until DATETIME DEFAULT NULL
        )
    """)

    c.execute("INSERT INTO users(username, password) VALUES ('admin', 'admin')") # Creates default admin user

    # Creates messages tables
    c.execute(""" #
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialised with fresh schema and default admin user.") # Logging indicates fresh schema


# Brute force
def is_locked_out(user_row) -> bool:
    lockout_until = user_row["lockout_until"] # Checks if lockout_until is in the future
    if not lockout_until:
        return False
    try:
        lock_dt = datetime.fromisoformat(lockout_until) # Prevents login until lock period ends
    except Exception:
        logger.warning("Invalid lockout_until format for user_id=%s", user_row["id"])
        return False
    return datetime.now() < lock_dt


# Session timeout enforcement
@app.before_request
def enforce_session_timeout():
    if "user_id" not in session:
        return
    now = int(time.time())
    last = session.get("last_activity")
    timeout = int(app.permanent_session_lifetime.total_seconds()) # session automatically expires and they must log in again

    if last is not None and now - last > timeout:
        user_id = session.get("user_id")
        logger.info(
            "Session timeout for user_id=%s ip=%s (inactive %ss > %ss)",
            user_id, get_client_ip(), now - last, timeout # Logs timeout 
        )
        session.clear()
        return redirect("/login") # Redirects to login

    session["last_activity"] = now
    session.permanent = True


# Update last seen
@app.before_request
def update_last_seen():
    # if frontend calls get_message 
    if "user_id" not in session or request.endpoint == "get_messages":
        return
    try:
        conn = setup_db()
        c = conn.cursor() # Executes the paramaterized queries to check user 
        c.execute("""
            UPDATE users SET last_seen = CURRENT_TIMESTAMP, is_online = 1
            WHERE id = ?
        """, (session["user_id"],))
        conn.commit()
    except Exception:
        logger.error(
            "Failed to update last_seen for user_id=%s ip=%s",
            session.get("user_id"), get_client_ip(), exc_info=True
        )
    finally:
        conn.close() 

# Helper to get online users
def get_online_users():
    conn = setup_db()
    c = conn.cursor() # Parameterized query to get updated user
    c.execute("""
        SELECT username FROM users
        WHERE last_seen > DATETIME('now', '-60 seconds') 
        ORDER BY username
    """)
    rows = c.fetchall()
    conn.close()
    return rows

def get_last_sender(user_id): # gets last sender 
    conn = setup_db()
    c = conn.cursor() # parameterized queries 
    c.execute("""
        SELECT u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = ?
        ORDER BY m.created_at DESC
        LIMIT 1
    """, (user_id,))
    row = c.fetchone()
    conn.close()
    return row["sender"] if row else None

# Routes
@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        raw_username = request.form.get("username", "")
        username = sanitize_username(raw_username).strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(username):
            logger.warning(
                "Registration rejected: invalid username format raw='%s' sanitized='%s' ip=%s",
                raw_username, username, get_client_ip()
            )
            return render_template("register.html", error="Invalid username.") # renders html or error

        hashed_pw = ph.hash(password) # Hashes password

        conn = setup_db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username, password) VALUES (?, ?)", # Parameterized queries to prevent SQL injection also checks if user is registered 
                      (username, hashed_pw))
            conn.commit()
            logger.info("User registered: username=%s ip=%s", username, get_client_ip())
            conn.close()
            return redirect("/login") # A
        except sqlite3.IntegrityError:
            conn.close()
            logger.warning(
                "Registration failed: username already exists username=%s ip=%s",
                username, get_client_ip()
            )
            return render_template("register.html", error="Username already exists")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        raw_username = request.form.get("username", "")
        username = sanitize_username(raw_username).strip()
        password = request.form.get("password", "")

        conn = setup_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,)) #parameterized queries to prevent SQL Injections
        user = c.fetchone()
        conn.close()

        ip = get_client_ip() # Sets ip with get_client_ip

        if not user:
            # Unknown username 
            logger.warning("Login failed: unknown username=%s ip=%s", username, ip)
            return render_template("login.html", error="Incorrect username or password")

        # Check if user locked out
        if is_locked_out(user):
            logger.warning(
                "Login attempt on locked account: user_id=%s username=%s ip=%s",
                user["id"], user["username"], ip
            )
            return render_template(
                "login.html",
                error="Account locked for 15 minutes due to too many failed attempts. Please try again later."
            )
        stored_pw = user["password"] 
        try:
            ph.verify(stored_pw, password) # Verifies password hashing

            # If hash needs rehash, upgrade it
            if ph.check_needs_rehash(stored_pw):
                new_hash = ph.hash(password)
                conn = setup_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
                conn.commit()
                conn.close()
                logger.info(
                    "Password hash upgraded (argon2 rehash) for user_id=%s username=%s",
                    user["id"], user["username"]
                )

            # Reset failed attempts
            conn = setup_db()
            c = conn.cursor()
            c.execute("""
                UPDATE users
                SET failed_attempts = 0,
                    lockout_until = NULL
                WHERE id = ?
            """, (user["id"],))
            conn.commit()
            conn.close()

            # Session cleared after logout 
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["last_activity"] = int(time.time())

            logger.info("Login success: user_id=%s username=%s ip=%s",
                        user["id"], user["username"], ip)

            return redirect("/dashboard") # if session active 

        except Exception:
            if stored_pw == password:
                new_hash = ph.hash(password)
                conn = setup_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
                conn.commit()

                # Reset failed attempts and  lockout on success
                c.execute("""
                    UPDATE users
                    SET failed_attempts = 0,
                        lockout_until = NULL
                    WHERE id = ?
                """, (user["id"],))
                conn.commit()
                conn.close()

                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["last_activity"] = int(time.time())

                logger.info(
                    "Login success using legacy plaintext password (auto-upgraded) user_id=%s username=%s ip=%s",
                    user["id"], user["username"], ip
                )

                return redirect("/dashboard")

            # Handle failed attempt
            conn = setup_db()
            c = conn.cursor()
            current_attempts = user["failed_attempts"] or 0
            new_attempts = current_attempts + 1
            lockout_until = None
            # Brute - force implementation 
            if new_attempts >= 4:  # if user fails attempt 4 time
                lock_time = datetime.now() + timedelta(minutes=15) # set lock out time 
                lockout_until = lock_time.isoformat()
                logger.warning(
                    "Account locked due to failed logins: user_id=%s username=%s attempts=%s ip=%s lockout_until=%s",
                    user["id"], user["username"], new_attempts, ip, lockout_until
                )
            else:
                logger.warning(
                    "Login failed: bad password user_id=%s username=%s attempts=%s ip=%s",
                    user["id"], user["username"], new_attempts, ip
                )
            #parameterized queries to check if users locked and how long left 
            c.execute("""
                UPDATE users
                SET failed_attempts = ?, lockout_until = ?
                WHERE id = ?
            """, (new_attempts, lockout_until, user["id"])) 
            conn.commit() 
            conn.close()

            return render_template("login.html", error="Incorrect username or password")
    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # user is logged in before accessing the dashboard
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    username = session["username"]
    error = None

    conn = setup_db()
    c = conn.cursor()

    if request.method == "POST":
        receiver_raw = request.form.get("receiver", "")

        # Sanitize username to prevent Unicode spoofing and invisible characters
        receiver = sanitize_username(receiver_raw)
        content = sanitize_message(request.form.get("content", ""))

        # Validate that a receiver was entered
        if receiver:
            # Store the chat in session so messages can load
            session["chat_with"] = receiver
            c.execute("SELECT id FROM users WHERE username=?", (receiver,))
            partner = c.fetchone()

            if partner:
                # Encrypt message before storing it in.
                encrypted = encrypt_message(content)

                # Insert encrypted message into the messages table
                c.execute("""
                    INSERT INTO messages(sender_id, receiver_id, content)
                    VALUES (?, ?, ?)
                """, (user_id, partner["id"], encrypted))
                conn.commit()
                logger.info(
                    "Message sent: from_user_id=%s to_user_id=%s content_length=%s ip=%s",
                    user_id, partner["id"], len(content), get_client_ip()
                )

            else:
                # Receiver username does not exist
                error = f"User '{receiver}' does not exist."
                logger.warning(
                    "Message send failed: receiver does not exist sender_user_id=%s receiver='%s' ip=%s",
                    user_id, receiver, get_client_ip()
                )
        else:
            # if sender left the receiver field blank
            error = "Recipient username required."
            logger.warning(
                "Message send failed: missing receiver sender_user_id=%s ip=%s",
                user_id, get_client_ip()
            )

    conn.close()
    # Gets active online users seen for last 60 seconds
    online_users = get_online_users()

    # Render the dashboard page with user info or error messages
    return render_template(
        "dashboard.html",
        username=username,
        online_users=online_users,
        preloaded_messages="",
        error=error
    )

@app.route("/get_messages")
def get_messages():
    # The user is logged in before allowing message retrieval
    if "user_id" not in session:
        logger.warning("get_messages called without session ip=%s", get_client_ip())
        return "<p>Error: Not logged in.</p>"

    user_id = session["user_id"]
    chat_with = session.get("chat_with")  # select chat partner

    # load the last person who messaged the user
    if not chat_with:
        last_sender = get_last_sender(user_id)
        if last_sender:
            session["chat_with"] = last_sender
            chat_with = last_sender
        else:
            # No available conversation history
            logger.info("No chat history found for user_id=%s", user_id)
            return "<p>No chat history found.</p>"

    # start db connection and look up the chat partner
    conn = setup_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (chat_with,))
    partner = c.fetchone()

    #receiver no longer exists or username invalid
    if not partner:
        conn.close()
        logger.warning(
            "get_messages receiver not found: user_id=%s chat_with='%s'",
            user_id, chat_with
        )
        return f"<p>User '{chat_with}' not found.</p>"

    partner_id = partner["id"]

    #  Paramaterized query all messages exchanged between the logged-in user and the partner
    c.execute("""
        SELECT m.content, m.created_at, u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE 
            (m.sender_id = ? AND m.receiver_id = ?)
         OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    """, (user_id, partner_id, partner_id, user_id))

    msgs = c.fetchall()
    conn.close()

    # create HTML output for all decrypted messages
    html = ""
    for msg in msgs:
        # Decrypt stored AES-GCM encrypted message before displaying
        decrypted = decrypt_message(msg["content"])

        # Render individual chat message bubble
        html += render_template_string("""
            <div class="message">
                <strong>{{ sender | e }}:</strong> {{ content | e }}<br>
                <small>{{ created_at }}</small>
            </div>
        """, sender=msg["sender"], content=decrypted, created_at=msg["created_at"])

    # Return the  HTML block into the chat window frontend
    return html


@app.route("/logout") # Log out the user
def logout():
    if "user_id" in session:
        uid = session["user_id"]
        conn = setup_db()
        c = conn.cursor()
        c.execute("UPDATE users SET is_online = 0 WHERE id=?", (uid,)) # Paramaterized queries to turn user offfline
        conn.commit()
        conn.close()
        logger.info("Logout: user_id=%s ip=%s", uid, get_client_ip())

    session.clear()
    return redirect("/login")


@app.errorhandler(CSRFError) # Detects CSRF attacks
def handle_csrf_error(e):
    logger.warning(
        "CSRF error on path=%s ip=%s reason=%s",
        request.path, get_client_ip(), getattr(e, "description", "CSRF token missing or invalid")
    )
    return jsonify({"error": "CSRF token missing or invalid"}), 400


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if isinstance(e, HTTPException):
        return e

    logger.exception(
        "Unhandled exception type=%s path=%s ip=%s",
        type(e).__name__, getattr(request, "path", "?"), get_client_ip()
    )
    # Generic response so the application doesnt leak internal info
    return "Internal server error. Please try again later.", 500


# Start main
if __name__ == "__main__":
    init_db() # Initialize db
    logger.info("Starting Encrypto Flask application.")
    app.run(debug=False, use_reloader=False)
