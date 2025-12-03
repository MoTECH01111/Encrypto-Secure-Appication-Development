from flask import Flask, request, redirect, session, render_template
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "insecure_key" 
DB_NAME = "insecure.db"


#DB setup
def setup_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if not os.path.exists(DB_NAME):
        conn = setup_db()
        c = conn.cursor()

        # users table insecure plaintext passwords
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                last_seen DATETIME,
                is_online INTEGER DEFAULT 0
            )
        """)

        # messages table
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

#Online
@app.before_request
def update_last_seen():
    if "user_id" in session:
        user_id = session["user_id"]
        conn = setup_db()
        c = conn.cursor()
        #using f-strings for SQL injection 
        c.execute(f"""
            UPDATE users
            SET last_seen = CURRENT_TIMESTAMP,
                is_online = 1
            WHERE id = {user_id}
        """)
        conn.commit()
        conn.close()


def get_online_users():
    conn = setup_db()
    c = conn.cursor()
    c.execute("""
        SELECT username FROM users
        WHERE last_seen > DATETIME('now', '-60 seconds')
        ORDER BY username
    """)
    users = c.fetchall()
    conn.close()
    return users


def get_last_sender(user_id):
    """Return the username of the last person who messaged this user, or None."""
    conn = setup_db()
    c = conn.cursor()
    c.execute(f"""
        SELECT u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = {user_id}
        ORDER BY m.created_at DESC
        LIMIT 1
    """)
    row = c.fetchone()
    conn.close()
    if row:
        return row["sender"]
    return None


@app.route("/get_messages")
def get_messages():
    if "user_id" not in session:
        return ""

    user_id = session["user_id"]
    chat_with = session.get("chat_with")

    if not chat_with:
        chat_with = get_last_sender(user_id)
        if chat_with:
            session["chat_with"] = chat_with
        else:
            return ""

    conn = setup_db()
    c = conn.cursor()

    c.execute(f"SELECT id FROM users WHERE username = '{chat_with}'")
    partner = c.fetchone()
    if not partner:
        conn.close()
        return ""

    partner_id = partner["id"]

    c.execute(f"""
        SELECT m.content, m.created_at, u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = {user_id} AND m.receiver_id = {partner_id})
           OR (m.sender_id = {partner_id} AND m.receiver_id = {user_id})
        ORDER BY m.created_at ASC
    """)
    messages = c.fetchall()
    conn.close()

    html = ""
    for msg in messages:
        html += f"""
        <div class="message">
            <strong>{msg['sender']}:</strong>
            <span style='white-space: pre-wrap;'>{msg['content']}</span><br>
            <small class="timestamp">{msg['created_at']}</small>
        </div>
        """
    return html


@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")

#Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = setup_db()
        c = conn.cursor()
        try:
            c.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
            conn.commit()
            conn.close()
            return redirect("/login")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Username already exists.")
    return render_template("register.html", error=None)

#Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = setup_db()
        c = conn.cursor()
        c.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        user = c.fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.pop("chat_with", None)
            return redirect("/dashboard")

        return render_template("login.html", error="Invalid login")
    return render_template("login.html", error=None)



#Dashboard
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    username = session["username"]

    conn = setup_db()
    c = conn.cursor()
    error = None

    if request.method == "POST":
        receiver = request.form.get("receiver", "").strip()
        content = request.form.get("content", "")

        if receiver:
            session["chat_with"] = receiver


            c.execute(f"SELECT id FROM users WHERE username='{receiver}'")
            row = c.fetchone()

            if row:
                receiver_id = row["id"]
                c.execute(f"""
                    INSERT INTO messages (sender_id, receiver_id, content)
                    VALUES ({user_id}, {receiver_id}, '{content}')
                """)
                conn.commit()
            else:
                error = f"User '{receiver}' does not exist"
        else:
            error = "You must enter a recipient username."

    conn.close()

    if not session.get("chat_with"):
        last_sender = get_last_sender(user_id)
        if last_sender:
            session["chat_with"] = last_sender

    online_users = get_online_users()

    return render_template(
        "dashboard.html",
        username=username,
        inbox=[],         
        error=error,
        online_users=online_users
    )


#Logout
@app.route("/logout")
def logout():
    if "user_id" in session:
        conn = setup_db()
        c = conn.cursor()
        c.execute(f"UPDATE users SET is_online = 0 WHERE id = {session['user_id']}")
        conn.commit()
        conn.close()

    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
