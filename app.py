import os
import secrets
import datetime
import traceback
import sqlite3
from functools import wraps
from flask import Flask, flash, redirect, render_template, request, session, g, url_for
from flask_session import Session
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

# Detect environment (Vercel or local)
IS_VERCEL = bool(os.environ.get("VERCEL"))

# Load .env only in local development
if not IS_VERCEL:
    load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

# Session configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Mail configuration
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "True").lower() in ["true", "1", "yes"]
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
mail = Mail(app)

# Database setup
DATABASE_URL = os.environ.get("DATABASE_URL", "password.db")


# ---------- Database Connection ---------- #
def get_db_connection():
    """Return database connection depending on environment"""
    if IS_VERCEL:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    else:
        conn = sqlite3.connect("password.db", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


# ---------- Utility Functions ---------- #
def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    if IS_VERCEL:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    else:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


# ---------- Routes ---------- #

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cursor = conn.cursor()

        if IS_VERCEL:
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        else:
            cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))

        if cursor.fetchone():
            conn.close()
            flash("Username or email already exists.", "warning")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        if IS_VERCEL:
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", 
                           (username, email, hashed_password))
        else:
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", 
                           (username, email, hashed_password))

        conn.commit()
        conn.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()

        if IS_VERCEL:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        else:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    if IS_VERCEL:
        cursor.execute("SELECT * FROM credentials WHERE user_id = %s", (session["user_id"],))
    else:
        cursor.execute("SELECT * FROM credentials WHERE user_id = ?", (session["user_id"],))

    credentials = cursor.fetchall()
    conn.close()
    return render_template("dashboard.html", credentials=credentials)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")

        conn = get_db_connection()
        cursor = conn.cursor()

        if IS_VERCEL:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

        user = cursor.fetchone()
        if not user:
            conn.close()
            flash("No account found with that email.", "warning")
            return redirect(url_for("forgot"))

        token = secrets.token_urlsafe(16)
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).isoformat()

        if IS_VERCEL:
            cursor.execute(
                "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                (user["id"], token, expires_at),
            )
        else:
            cursor.execute(
                "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                (user["id"], token, expires_at),
            )

        conn.commit()
        conn.close()

        reset_link = f"{request.host_url}reset/{token}"
        msg = Message("Password Reset Request", sender=app.config["MAIL_USERNAME"], recipients=[email])
        msg.body = f"Click the link to reset your password: {reset_link}\nThis link expires in 15 minutes."
        mail.send(msg)

        flash("Password reset link sent to your email!", "info")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    conn = get_db_connection()
    cursor = conn.cursor()

    if IS_VERCEL:
        cursor.execute("SELECT * FROM password_reset_tokens WHERE token = %s", (token,))
    else:
        cursor.execute("SELECT * FROM password_reset_tokens WHERE token = ?", (token,))

    token_data = cursor.fetchone()
    if not token_data:
        conn.close()
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form.get("password")
        hashed_password = generate_password_hash(new_password)

        if IS_VERCEL:
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", 
                           (hashed_password, token_data["user_id"]))
            cursor.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
        else:
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                           (hashed_password, token_data["user_id"]))
            cursor.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))

        conn.commit()
        conn.close()
        flash("Password reset successful! You can now log in.", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset.html", token=token)


# ---------- Error Handling ---------- #
@app.errorhandler(Exception)
def handle_exception(e):
    print("🔥 ERROR TRACEBACK 🔥")
    traceback.print_exc()
    return render_template("error.html", message=str(e)), 500


# ---------- Run ---------- #
if __name__ == "__main__":
    app.run(debug=not IS_VERCEL)
