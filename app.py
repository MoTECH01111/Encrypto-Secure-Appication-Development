from flask import Flask, request, redirect, session, render_template
import sqlite3
from datetime import datetime
from argon2 import PasswordHasher

app = Flask(__name__)
ph = PasswordHasher()
app.secret_key = "insecure_key"

DB_NAME = "secure.db"

#Setting up db
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


#Auto update
@app.before_request
def update_last_seen():
    if "user_id" not in session:
        return

    # Prevent last_seen updates during /get_messages fetch 
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



#Helpers
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


#Routes
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
        if "<script>" in username:
            return render_template("register.html", error=username)

        conn = setup_db()
        c = conn.cursor()
        try:
            hashed_pw = ph.hash(password)

            c.execute(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                (username, hashed_pw)
            )
            
            conn.commit()
            conn.close()
            return redirect("/login")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error=f"Registration failed for: {username}")

    return render_template("register.html")

#Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = setup_db()
        c = conn.cursor()

        query = f"""
            SELECT *
            FROM users
            WHERE (username='{username}' AND password='{password}')
            OR '1'='1'
            ORDER BY (username='{username}' AND password='{password}') DESC
        """
        print("SQL Query:", query)

        try:
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            print("SQL ERROR:", e)
            user = None

            conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.pop("chat_with", None)
            return redirect("/dashboard")

        return render_template("login.html", error="Incorrect username or password")

    return render_template("login.html", error=None)

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

    #Send message
    if request.method == "POST":
        receiver = request.form.get("receiver", "").strip()
        content = request.form.get("content", "")

        if receiver:
            session["chat_with"] = receiver

            c.execute("SELECT id FROM users WHERE username=?", (receiver,))
            partner = c.fetchone()

            if partner:
                receiver_id = partner["id"]
                c.execute("""
                    INSERT INTO messages(sender_id, receiver_id, content)
                    VALUES (?, ?, ?)
                """, (user_id, receiver_id, content))
                conn.commit()
            else:
                error = f"User '{receiver}' does not exist."
        else:
            error = "Recipient username required."

    conn.close()

    online_users = get_online_users()
    preloaded_messages = ""

    return render_template(
        "dashboard.html",
        username=username,
        online_users=online_users,
        preloaded_messages=preloaded_messages,
        error=error,
    )


#Get messages 
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

    c.execute("""
        SELECT m.content, m.created_at, u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id=? AND m.receiver_id=?)
           OR (m.sender_id=? AND m.receiver_id=?)
        ORDER BY m.created_at ASC
    """, (user_id, partner_id, partner_id, user_id))

    msgs = c.fetchall()
    conn.close()

    html = ""
    for msg in msgs:
        html += f"""
            <div class="message">
                <strong>{msg['sender']}:</strong> {msg["content"]}<br>
                <small>{msg['created_at']}</small>
            </div>
        """

    return html

#logout
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

#Start main
if __name__ == "__main__":
    init_db()
    app.run(debug=False, use_reloader=False)
