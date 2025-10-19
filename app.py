import os
import secrets
import datetime
from functools import wraps
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, g, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from email_service import email_service
from flask_mail import Mail, Message

app = Flask(__name__)

load_dotenv() 

DATABASESQL = os.getenv("DATABASE")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'your-app-password')
TESTING_MODE = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_USERNAME

mail = Mail(app)

DATABASE = DATABASESQL

def init_db():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            website TEXT,
            username TEXT,
            password_encrypted TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    db.commit()
    db.close()


if not os.path.exists(DATABASE):
    init_db()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def load_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        g.user = row


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = "0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            flash("Username is required!", "error")
            return redirect(url_for("login"))
        elif not password:
            flash("must provide password", "error")
            return redirect(url_for("login"))
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            flash("invalid username and/or password", "error")
            return redirect(url_for("login"))
        session["user_id"] = row["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        email = request.form.get("email")
        db = get_db()
        if not username:
            flash("Username is required!", "error")
            return redirect(url_for("register"))
        elif not email:
            flash("Email is required!", "error")
            return redirect(url_for("register"))
        elif not password:
            flash("Password is required!", "error")
            return redirect(url_for("register"))
        elif not confirmation:
            flash("Confirm Password is required!", "error")
            return redirect(url_for("register"))
        elif password != confirmation:
            flash("Password doesn't Match!", "error")
            return redirect(url_for("register"))
        

        row = db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
        if row is not None:
            flash("Username Already Present", "error")
            return redirect(url_for("register"))

        hash_pw = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hash_pw, email))
        db.commit()

        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        session["user_id"] = row["id"]

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/")
@login_required
def vault():
    db = get_db()
    credentials = db.execute(
        "SELECT * FROM credentials WHERE user_id = ?", (g.user["id"],)
    ).fetchall()
    return render_template("vault.html", credentials=credentials)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        website = request.form.get("website")
        username = request.form.get("username")
        password = request.form.get("password")

        if not website or not username or not password:
            flash("All fields are required!", "error")
            return redirect(url_for("add"))

        db = get_db()
        db.execute(
            "INSERT INTO credentials (user_id, website, username, password_encrypted) VALUES (?, ?, ?, ?)",
            (g.user["id"], website, username, password)
        )
        db.commit()
        flash("Credential added successfully!", "success")
        return redirect("/")

    return render_template("add.html")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    db = get_db()

    if request.method == "POST":
        if "change_password" in request.form:
            prev_password = request.form.get("prev_password")
            new_password = request.form.get("new_password")

            if not prev_password or not new_password:
                flash("All fields are required!", "error")
                return redirect(url_for("account"))
            if not check_password_hash(g.user["password_hash"], prev_password):
                flash("Previous password is incorrect", "error")
                return redirect(url_for("account"))
            new_hash = generate_password_hash(new_password)
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, g.user["id"]))
            db.commit()
            flash("Password changed successfully!", "success")
            return redirect(url_for("account"))

        elif "change_email" in request.form:
            new_email = request.form.get("new_email")
            if not new_email:
                flash("Email cannot be empty!", "error")
                return redirect(url_for("account"))

            # check if email is already taken
            existing = db.execute("SELECT id FROM users WHERE email = ?", (new_email,)).fetchone()
            if existing:
                flash("This email is already in use!", "error")
                return redirect(url_for("account"))

            db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, g.user["id"]))
            db.commit()
            flash("Email updated successfully!", "success")
            return redirect(url_for("account"))

        elif "delete_account" in request.form:
            db.execute("DELETE FROM credentials WHERE user_id = ?", (g.user["id"],))
            db.execute("DELETE FROM users WHERE id = ?", (g.user["id"],))
            db.commit()
            session.clear()
            flash("Account deleted successfully!", "success")
            return redirect(url_for("register"))

    return render_template("account.html")

@app.route("/update/<int:cred_id>", methods=["GET", "POST"])
@login_required
def update_credential(cred_id):
    db = get_db()
    cred = db.execute(
        "SELECT * FROM credentials WHERE id = ? AND user_id = ?", 
        (cred_id, g.user["id"])
    ).fetchone()

    if not cred:
        flash("Credential not found!", "error")
        return redirect(url_for("vault"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("All fields are required!", "error")
            return redirect(url_for("update_credential", cred_id=cred_id))

        db.execute(
            "UPDATE credentials SET username = ?, password_encrypted = ? WHERE id = ?",
            (username, password, cred_id)
        )
        db.commit()
        flash("Credential updated successfully!", "success")
        return redirect(url_for("vault"))

    return render_template("update.html", cred=cred)

@app.route("/delete/<int:cred_id>", methods=["POST"])
@login_required
def delete_credential(cred_id):
    db = get_db()
    db.execute(
        "DELETE FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, g.user["id"])
    )
    db.commit()
    flash("Credential deleted successfully!", "success")
    return redirect(url_for("vault"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Email is required!", "error")
            return redirect(url_for("forgot"))
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
            
            db.execute("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                       (user["id"], token, expires_at))
            db.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            msg_body = f"""
                <html>
                <head>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            margin: 0;
                            padding: 0;
                        }}
                        .container {{
                            background-color: #ffffff;
                            width: 90%;
                            max-width: 600px;
                            margin: 50px auto;
                            padding: 20px;
                            border-radius: 10px;
                            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
                        }}
                        h2 {{
                            color: #333333;
                        }}
                        p {{
                            color: #555555;
                            line-height: 1.5;
                        }}
                        .button {{
                            display: inline-block;
                            padding: 12px 25px;
                            margin-top: 20px;
                            background-color: #007BFF;
                            color: #ffffff;
                            text-decoration: none;
                            border-radius: 5px;
                            font-weight: bold;
                        }}
                        .footer {{
                            margin-top: 30px;
                            font-size: 12px;
                            color: #888888;
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Password Reset Request</h2>
                        <p>Hello {user['username']},</p>
                        <p>You have requested to reset your password for <strong>PassGuard</strong>.</p>
                        <p>Click the button below to reset your password. This link will expire in <strong>1 hour</strong>:</p>
                        <a href="{reset_url}" class="button">Reset Password</a>
                        <p>If you did not request this password reset, please ignore this email.</p>
                        <div class="footer">
                            Best regards,<br>
                            <strong>PassGuard Team</strong>
                        </div>
                    </div>
                </body>
                </html>
                """
            
            try:
                if TESTING_MODE:
                    flash(f"Password reset link: {reset_url}", "success")
                    print(f"Reset URL: {reset_url}")
                else:
                    success, message = email_service.send_email(
                        to_email=email,
                        subject='Password Reset Request - PassGuard',
                        body=msg_body,
                        from_email=MAIL_USERNAME,
                        password=MAIL_PASSWORD,
                        method='yagmail',
                        provider='gmail'
                    )
                    
                    if success:
                        flash("Password reset instructions have been sent to your email!", "success")
                    else:
                        flash(f"Email failed: {message}", "error")
                        flash(f"Reset link: {reset_url}", "info")
                        
            except Exception as e:
                flash("Failed to send email. Please try again later.", "error")
                print(f"Email error: {e}")
                flash(f"Reset link: {reset_url}", "info")
        else:
            flash("No account found with that email address.", "error")
        
        return redirect(url_for("forgot"))
    
    return render_template("forgot.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    token_record = db.execute(
        "SELECT * FROM password_reset_tokens WHERE token = ? AND used = FALSE AND expires_at > ?",
        (token, datetime.datetime.now())
    ).fetchone()

    if not token_record:
        flash("Invalid or expired reset token!", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            flash("All fields are required!", "error")
            return redirect(url_for("reset_password", token=token))

        if new_password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("reset_password", token=token))

        new_hash = generate_password_hash(new_password)
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, token_record["user_id"])
        )
        db.execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE id = ?",
            (token_record["id"],)
        )
        db.commit()
        flash("Password reset successfully! You can now log in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

if __name__ == '__main__':
    app.run()