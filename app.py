from flask import Flask, request, redirect, session, render_template, render_template_string
import sqlite3
from datetime import datetime, timedelta
from argon2 import PasswordHasher
import re
import os
import json
import base64
import hashlib
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_NAME = "secure.db"

# Persistent Secret key
SECRET_FILE = "secret.key"

def load_or_create_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            return f.read()
    key = os.urandom(64)  # 512-bit secret
    with open(SECRET_FILE, "wb") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = load_or_create_secret_key()


#Secure cookie & session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,   
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)  # session timeout
)

# Argon2id Hash
ph = PasswordHasher()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# AES-GCM Encryption
KEY_FILE = "key.json"


def load_or_create_key():
    """
    Load a 64-byte master key from file, or create it if missing.
    Stored as hex string; keep key.json out of repo via .gitignore.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            data = json.load(f)
            return data["MASTER_KEY"]

    # 64 random bytes -> 128 hex chars
    master_key_bytes = os.urandom(64)
    master_key_hex = master_key_bytes.hex()

    with open(KEY_FILE, "w") as f:
        json.dump({"MASTER_KEY": master_key_hex}, f, indent=4)

    return master_key_hex


MASTER_KEY_HEX = load_or_create_key()
MASTER_KEY_BYTES = bytes.fromhex(MASTER_KEY_HEX)

# Derive a 32-byte AES key (256-bit) from the 64-byte master via SHA-256
AES_KEY = hashlib.sha256(MASTER_KEY_BYTES).digest()

aesgcm = AESGCM(AES_KEY)


def encrypt_message(plaintext: str) -> str:
    """
    Encrypt message using AES-256-GCM.
    Returns base64url-encoded string containing nonce + ciphertext.
    """
    if plaintext is None:
        plaintext = ""
    nonce = os.urandom(12)  # Recommended size for GCM
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = nonce + ct
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_message(token: str) -> str:
    """
    Decrypt base64url-encoded nonce + ciphertext.
    Returns plaintext string or error placeholder.
    """
    try:
        data = base64.urlsafe_b64decode(token.encode("ascii"))
        nonce = data[:12]
        ct = data[12:]
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception:
        return "[DECRYPTION ERROR]"


# Setting up db
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
            is_online INTEGER DEFAULT 0
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


# -----------------------------
#  SESSION TIMEOUT ENFORCEMENT
# -----------------------------
@app.before_request
def enforce_session_timeout():
    """
    Enforce inactivity timeout using server-side timestamp.
    """
    if "user_id" not in session:
        return

    now = int(time.time())
    last = session.get("last_activity")
    timeout = int(app.permanent_session_lifetime.total_seconds())

    if last is not None and now - last > timeout:
        session.clear()
        return redirect("/login")

    session["last_activity"] = now
    session.permanent = True


# Auto update last_seen
@app.before_request
def update_last_seen():
    if "user_id" not in session:
        return
    
    if request.endpoint == "get_messages":
        return

    try:
        conn = setup_db()
        c = conn.cursor()
        c.execute("""
            UPDATE users
            SET last_seen = CURRENT_TIMESTAMP,
                is_online = 1
            WHERE id = ?
        """, (session["user_id"],))
        conn.commit()
    except:
        pass
    finally:
        conn.close()


# Helpers
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


# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            return render_template("register.html", error="Username must be 3–32 chars (letters, numbers, underscore).")

        hashed_pw = ph.hash(password)

        conn = setup_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                (username, hashed_pw)
            )
            conn.commit()
            conn.close()
            return redirect("/login")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Username already exists")

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = setup_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if not user:
            return render_template("login.html", error="Incorrect username or password")

        stored_pw = user["password"]

        try:
            ph.verify(stored_pw, password)

            if ph.check_needs_rehash(stored_pw):
                new_hash = ph.hash(password)
                conn = setup_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
                conn.commit()
                conn.close()

            # generate session ID on successful login
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["last_activity"] = int(time.time())
            session.pop("chat_with", None)
            return redirect("/dashboard")

        except Exception:
            # Legacy plaintext fallback
            if stored_pw == password:
                new_hash = ph.hash(password)
                conn = setup_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))
                conn.commit()
                conn.close()

                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["last_activity"] = int(time.time())
                session.pop("chat_with", None)
                return redirect("/dashboard")

            return render_template("login.html", error="Incorrect username or password")

    return render_template("login.html")


# Dashboard
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    username = session["username"]
    error = None

    conn = setup_db()
    c = conn.cursor()

    # Send message
    if request.method == "POST":
        receiver = request.form.get("receiver", "").strip()
        content = request.form.get("content", "")

        if receiver:
            session["chat_with"] = receiver

            # User lookup is parameterized
            c.execute("SELECT id FROM users WHERE username=?", (receiver,))
            partner = c.fetchone()

            if partner:
                receiver_id = partner["id"]

                # Encrypt message before storing using AES-GCM
                encrypted_content = encrypt_message(content)

                c.execute("""
                    INSERT INTO messages(sender_id, receiver_id, content)
                    VALUES (?, ?, ?)
                """, (user_id, receiver_id, encrypted_content))
                conn.commit()
            else:
                error = f"User '{receiver}' does not exist."
        else:
            error = "Recipient username required."

    conn.close()

    online_users = get_online_users()

    return render_template(
        "dashboard.html",
        username=username,
        online_users=online_users,
        preloaded_messages="",
        error=error,
    )


# Get messages
@app.route("/get_messages")
def get_messages():
    if "user_id" not in session:
        return "<p>Error: Not logged in.</p>"

    user_id = session["user_id"]
    chat_with = session.get("chat_with")

    if not chat_with:
        last_sender = get_last_sender(user_id)
        if last_sender:
            session["chat_with"] = last_sender
            chat_with = last_sender
        else:
            return "<p>No chat history found.</p>"

    conn = setup_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (chat_with,))
    partner = c.fetchone()

    if not partner:
        conn.close()
        return f"<p>User '{chat_with}' not found.</p>"

    partner_id = partner["id"]

    # Query ensures the logged-in user is always sender or receiver
    c.execute("""
        SELECT m.content, m.created_at, u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE
            (m.sender_id = ? AND m.receiver_id = ?)
            OR
            (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    """, (user_id, partner_id, partner_id, user_id))

    msgs = c.fetchall()
    conn.close()

    html = ""
    for msg in msgs:
        # Decrypt message before showing
        decrypted = decrypt_message(msg["content"])

        html += render_template_string(
            """
            <div class="message">
                <strong>{{ sender | e }}:</strong> {{ content | e }}<br>
                <small>{{ created_at }}</small>
            </div>
            """,
            sender=msg["sender"],
            content=decrypted,
            created_at=msg["created_at"]
        )

    return html

# Logout
@app.route("/logout")
def logout():
    if "user_id" in session:
        conn = setup_db()
        c = conn.cursor()
        c.execute("UPDATE users SET is_online = 0 WHERE id=?", (session["user_id"],))
        conn.commit()
        conn.close()

    session.clear()
    return redirect("/login")


# Start main
if __name__ == "__main__":
    init_db()
    app.run(debug=False, use_reloader=False)
