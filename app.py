from flask import Flask, request, redirect, session, render_template, render_template_string, jsonify
import sqlite3
from datetime import datetime, timedelta
from argon2 import PasswordHasher
import re
import os
import json
import base64
import hashlib
import time
import logging
from logging.handlers import RotatingFileHandler
import unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.exceptions import HTTPException

DB_NAME = "secure.db"

# logging config
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("encrypto_app")
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "app.log"),
        maxBytes=1_000_000,   # 1MB per file
        backupCount=5         
    )
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s %(message)s"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def get_client_ip() -> str:
    """Return client IP for logging (no trust/security assumptions)."""
    try:
        return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    except RuntimeError:
        return "unknown"

# Persistent Secret key
SECRET_FILE = "secret.key"

def load_or_create_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            key = f.read()
            logger.info("Loaded existing Flask secret key from disk.")
            return key
    key = os.urandom(64)  # 512-bit secret
    with open(SECRET_FILE, "wb") as f:
        f.write(key)
    logger.warning("Generated new Flask secret key no keys were  found.")
    return key


app = Flask(__name__)
app.secret_key = load_or_create_secret_key()
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = None

csrf = CSRFProtect(app)

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


# Sanitizer
def sanitize_username(username: str) -> str:
    """Remove invisible, control, and unsafe Unicode from usernames."""
    if not isinstance(username, str):
        return ""
    username = unicodedata.normalize("NFKC", username)

    cleaned = []
    for ch in username:
        category = unicodedata.category(ch)

        if category.startswith("C"):
            continue
        if category == "Mn":
            continue
        if ch.isspace():
            continue

        cleaned.append(ch)

    return "".join(cleaned)


def sanitize_message(text: str) -> str:
    """Remove invisible control/unicode attacks while allowing emojis."""
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKC", text)

    cleaned = []
    for ch in text:
        cat = unicodedata.category(ch)

        if cat.startswith("C"):
            continue
        if ch in ["\u202E", "\u202D", "\u202B", "\u2066", "\u2067"]:
            continue

        cleaned.append(ch)

    return "".join(cleaned)


# AES-GCM Encryption
KEY_FILE = "key.json"

def load_or_create_key():
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

MASTER_KEY_HEX = load_or_create_key()
AES_KEY = hashlib.sha256(bytes.fromhex(MASTER_KEY_HEX)).digest()
aesgcm = AESGCM(AES_KEY)


def encrypt_message(plaintext: str) -> str:
    plaintext = sanitize_message(plaintext)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_message(token: str) -> str:
    try:
        data = base64.urlsafe_b64decode(token.encode())
        nonce = data[:12]
        ct = data[12:]
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode()
    except Exception:
        # Do not log token contents
        logger.error("Decryption error for stored message token.", exc_info=True)
        return "[DECRYPTION ERROR]"


# Db setup
def setup_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = setup_db()
    c = conn.cursor()

    c.execute("DROP TABLE IF EXISTS messages")
    c.execute("DROP TABLE IF EXISTS users")

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

    c.execute("INSERT INTO users(username, password) VALUES ('admin', 'admin')")

    c.execute("""
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
    logger.info("Database initialised with fresh schema and default admin user.")


# Brute force
def is_locked_out(user_row) -> bool:
    lockout_until = user_row["lockout_until"]
    if not lockout_until:
        return False
    try:
        lock_dt = datetime.fromisoformat(lockout_until)
    except Exception:
        logger.warning("Invalid lockout_until format for user_id=%s", user_row["id"])
        return False
    return datetime.now() < lock_dt


# Session Timeout
@app.before_request
def enforce_session_timeout():
    if "user_id" not in session:
        return
    now = int(time.time())
    last = session.get("last_activity")
    timeout = int(app.permanent_session_lifetime.total_seconds())

    if last is not None and now - last > timeout:
        user_id = session.get("user_id")
        logger.info(
            "Session timeout for user_id=%s ip=%s (inactive %ss > %ss)",
            user_id, get_client_ip(), now - last, timeout
        )
        session.clear()
        return redirect("/login")

    session["last_activity"] = now
    session.permanent = True


# Update last seen
@app.before_request
def update_last_seen():
    if "user_id" not in session or request.endpoint == "get_messages":
        return
    try:
        conn = setup_db()
        c = conn.cursor()
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


# Helper
def get_online_users():
    conn = setup_db()
    c = conn.cursor()
    c.execute("""
        SELECT username FROM users
        WHERE last_seen > DATETIME('now', '-60 seconds')
        ORDER BY username
    """)
    rows = c.fetchall()
    conn.close()
    return rows


def get_last_sender(user_id):
    conn = setup_db()
    c = conn.cursor()
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
            return render_template("register.html", error="Invalid username.")

        hashed_pw = ph.hash(password)

        conn = setup_db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username, password) VALUES (?, ?)",
                      (username, hashed_pw))
            conn.commit()
            logger.info("User registered: username=%s ip=%s", username, get_client_ip())
            conn.close()
            return redirect("/login")
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
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        ip = get_client_ip()

        if not user:
            # Unknown username 
            logger.warning("Login failed: unknown username=%s ip=%s", username, ip)
            return render_template("login.html", error="Incorrect username or password")

        # Check lockout
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
            ph.verify(stored_pw, password)

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

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["last_activity"] = int(time.time())

            logger.info("Login success: user_id=%s username=%s ip=%s",
                        user["id"], user["username"], ip)

            return redirect("/dashboard")

        except Exception:
            if stored_pw == password:
                new_hash = ph.hash(password)
                conn = setup_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
                conn.commit()

                # Reset failed attempts + lockout on success
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

            if new_attempts >= 4:
                lock_time = datetime.now() + timedelta(minutes=15)
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
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    username = session["username"]
    error = None

    conn = setup_db()
    c = conn.cursor()

    if request.method == "POST":
        receiver_raw = request.form.get("receiver", "")
        receiver = sanitize_username(receiver_raw)
        content = sanitize_message(request.form.get("content", ""))

        if receiver:
            session["chat_with"] = receiver
            c.execute("SELECT id FROM users WHERE username=?", (receiver,))
            partner = c.fetchone()

            if partner:
                encrypted = encrypt_message(content)
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
                error = f"User '{receiver}' does not exist."
                logger.warning(
                    "Message send failed: receiver does not exist sender_user_id=%s receiver='%s' ip=%s",
                    user_id, receiver, get_client_ip()
                )
        else:
            error = "Recipient username required."
            logger.warning(
                "Message send failed: missing receiver sender_user_id=%s ip=%s",
                user_id, get_client_ip()
            )

    conn.close()
    online_users = get_online_users()

    return render_template(
        "dashboard.html",
        username=username,
        online_users=online_users,
        preloaded_messages="",
        error=error
    )


@app.route("/get_messages")
def get_messages():
    if "user_id" not in session:
        logger.warning("get_messages called without session ip=%s", get_client_ip())
        return "<p>Error: Not logged in.</p>"

    user_id = session["user_id"]
    chat_with = session.get("chat_with")

    if not chat_with:
        last_sender = get_last_sender(user_id)
        if last_sender:
            session["chat_with"] = last_sender
            chat_with = last_sender
        else:
            logger.info("No chat history found for user_id=%s", user_id)
            return "<p>No chat history found.</p>"

    conn = setup_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (chat_with,))
    partner = c.fetchone()

    if not partner:
        conn.close()
        logger.warning(
            "get_messages receiver not found: user_id=%s chat_with='%s'",
            user_id, chat_with
        )
        return f"<p>User '{chat_with}' not found.</p>"

    partner_id = partner["id"]

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

    html = ""
    for msg in msgs:
        decrypted = decrypt_message(msg["content"])

        html += render_template_string("""
            <div class="message">
                <strong>{{ sender | e }}:</strong> {{ content | e }}<br>
                <small>{{ created_at }}</small>
            </div>
        """, sender=msg["sender"], content=decrypted, created_at=msg["created_at"])

    return html


@app.route("/logout")
def logout():
    if "user_id" in session:
        uid = session["user_id"]
        conn = setup_db()
        c = conn.cursor()
        c.execute("UPDATE users SET is_online = 0 WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        logger.info("Logout: user_id=%s ip=%s", uid, get_client_ip())

    session.clear()
    return redirect("/login")


@app.errorhandler(CSRFError)
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
    init_db()
    logger.info("Starting Encrypto Flask application.")
    app.run(debug=False, use_reloader=False)
