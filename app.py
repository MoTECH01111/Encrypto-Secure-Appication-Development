from flask import Flask, request, redirect, session, render_template
import sqlite3
import os

app = Flask(__name__)


app.secret_key = "insecure_key"

DB_NAME = "insecure"


# DB setup
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if not os.path.exists(DB_NAME):
        conn = get_db()
        c = conn.cursor()

        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

       
        c.execute("""
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        """)

        conn.commit()
        conn.close()


#Index  
@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        c = conn.cursor()
        try:

            query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
            c.execute(query)
            conn.commit()
            conn.close()
            return redirect("/login")
        except sqlite3.IntegrityError:
            conn.close()
            
            return render_template("register.html", error="Username already exists.")

    return render_template("register.html", error=None)



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        c = conn.cursor()

      
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid credentials (no lockout).")

    return render_template("login.html", error=None)


#Dashboard 
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    username = session["username"]

    conn = get_db()
    c = conn.cursor()

    error = None


    if request.method == "POST":
        receiver_username = request.form.get("receiver", "")
        content = request.form.get("content", "")

    
        query_user = f"SELECT id FROM users WHERE username = '{receiver_username}'"
        c.execute(query_user)
        receiver = c.fetchone()

        if receiver:
            receiver_id = receiver["id"]

            
            query_msg = f"""
                INSERT INTO messages (sender_id, receiver_id, content)
                VALUES ({user_id}, {receiver_id}, '{content}')
            """
            c.execute(query_msg)
            conn.commit()
        else:

            error = f"User '{receiver_username}' does not exist."


    query_inbox = f"""
        SELECT m.content, m.created_at, u.username AS sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = {user_id}
        ORDER BY m.created_at DESC
    """
    c.execute(query_inbox)
    inbox = c.fetchall()
    conn.close()


    return render_template("dashboard.html", username=username, inbox=inbox, error=error)

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
