import os
import secrets
import datetime
from functools import wraps
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, g, url_for
from flask_session import Session
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from email_service import email_service
from dotenv import load_dotenv

# Detect if running on Vercel
IS_VERCEL = bool(os.environ.get('VERCEL'))

# Load .env file only for local development
try:
    if not IS_VERCEL:
        load_dotenv('environment.txt')
except ImportError:
    pass

app = Flask(__name__)

# Get SECRET_KEY from environment variable
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Generate a random secret key if not provided
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: Using generated SECRET_KEY. Set SECRET_KEY in Vercel environment variables.")

app.config['SECRET_KEY'] = SECRET_KEY
app.config["SESSION_PERMANENT"] = False

# Session configuration
if not IS_VERCEL:
    app.config["SESSION_TYPE"] = "filesystem"
    Session(app)
else:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_HTTPONLY'] = True

# Get email configuration from environment variables
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
TESTING_MODE = os.environ.get('TESTING_MODE', 'False').lower() == 'true'

# Validate that email credentials are provided
if not MAIL_USERNAME or not MAIL_PASSWORD:
    print("WARNING: MAIL_USERNAME or MAIL_PASSWORD not set in environment variables.")
    print("Email functionality will not work properly.")

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_USERNAME

mail = Mail(app)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///password.db')

def _is_postgres(url: str) -> bool:
    return url.startswith('postgres://') or url.startswith('postgresql://')

IS_POSTGRES = _is_postgres(DATABASE_URL)

if IS_POSTGRES:
    DATABASE = DATABASE_URL
else:
    DATABASE = "password.db"

def get_db():
    if "db" not in g:
        if IS_POSTGRES:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        else:
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
    return g.db

def _normalize_query(query: str) -> str:
    return query.replace('?', '%s') if IS_POSTGRES else query

def db_execute(query, params=(), commit=False):
    db = get_db()
    if IS_POSTGRES:
        cur = db.cursor()
        cur.execute(_normalize_query(query), params)
    else:
        cur = db.execute(query, params)
    if commit:
        db.commit()
    return cur

def db_commit():
    db = get_db()
    db.commit()

def db_query_one(query, params=()):
    cur = db_execute(query, params)
    return cur.fetchone()

def db_query_all(query, params=()):
    cur = db_execute(query, params)
    return cur.fetchall()

# Initialize database
try:
    from init_db import init_sqlite_db, init_postgresql_db
    if IS_POSTGRES:
        init_postgresql_db()
    else:
        init_sqlite_db()
except Exception as e:
    print(f"Database initialization skipped: {e}")

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
        row = db_query_one("SELECT * FROM users WHERE id = ?", (user_id,))
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
        
        row = db_query_one("SELECT * FROM users WHERE username = ?", (username,))
        
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
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
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
        
        # Check if username already exists
        row = db_query_one("SELECT username FROM users WHERE username = ?", (username,))
        if row is not None:
            flash("Username Already Present", "error")
            return redirect(url_for("register"))
        
        # Check if email already exists
        row = db_query_one("SELECT email FROM users WHERE email = ?", (email,))
        if row is not None:
            flash("Email Already Registered", "error")
            return redirect(url_for("register"))
        
        hash_pw = generate_password_hash(password)
        db_execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hash_pw),
            commit=True,
        )
        
        row = db_query_one("SELECT * FROM users WHERE username = ?", (username,))
        session["user_id"] = row["id"]
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/")
@login_required
def vault():
    credentials = db_query_all(
        "SELECT * FROM credentials WHERE user_id = ?", (g.user["id"],)
    )
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
        
        db_execute(
            "INSERT INTO credentials (user_id, website, username, password_encrypted) VALUES (?, ?, ?, ?)",
            (g.user["id"], website, username, password),
            commit=True
        )
        
        flash("Credential added successfully!", "success")
        return redirect("/")
    
    return render_template("add.html")

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
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
            db_execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, g.user["id"]), commit=True)
            
            flash("Password changed successfully!", "success")
            return redirect(url_for("account"))
        
        elif "change_email" in request.form:
            new_email = request.form.get("new_email")
            
            if not new_email:
                flash("Email cannot be empty!", "error")
                return redirect(url_for("account"))
            
            existing = db_query_one("SELECT id FROM users WHERE email = ?", (new_email,))
            if existing:
                flash("This email is already in use!", "error")
                return redirect(url_for("account"))
            
            db_execute("UPDATE users SET email = ? WHERE id = ?", (new_email, g.user["id"]), commit=True)
            
            flash("Email updated successfully!", "success")
            return redirect(url_for("account"))
        
        elif "delete_account" in request.form:
            db_execute("DELETE FROM credentials WHERE user_id = ?", (g.user["id"],), commit=True)
            db_execute("DELETE FROM users WHERE id = ?", (g.user["id"],), commit=True)
            session.clear()
            flash("Account deleted successfully!", "success")
            return redirect(url_for("register"))
    
    return render_template("account.html")

@app.route("/update/<int:cred_id>", methods=["GET", "POST"])
@login_required
def update_credential(cred_id):
    cred = db_query_one(
        "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, g.user["id"])
    )
    
    if not cred:
        flash("Credential not found!", "error")
        return redirect(url_for("vault"))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("All fields are required!", "error")
            return redirect(url_for("update_credential", cred_id=cred_id))
        
        db_execute(
            "UPDATE credentials SET username = ?, password_encrypted = ? WHERE id = ?",
            (username, password, cred_id),
            commit=True
        )
        
        flash("Credential updated successfully!", "success")
        return redirect(url_for("vault"))
    
    return render_template("update.html", cred=cred)

@app.route("/delete/<int:cred_id>", methods=["POST"])
@login_required
def delete_credential(cred_id):
    db_execute(
        "DELETE FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, g.user["id"]),
        commit=True
    )
    
    flash("Credential deleted successfully!", "success")
    return redirect(url_for("vault"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")
        
        if not email:
            flash("Email is required!", "error")
            return redirect(url_for("forgot"))
        
        user = db_query_one("SELECT * FROM users WHERE email = ?", (email,))
        
        if user:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
            
            db_execute("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                      (user["id"], token, expires_at), commit=True)
            
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg_body = f'''
Password Reset Request

Hello {user['username']},

You have requested to reset your password for AuthGuard.

Click the button below to reset your password. This link will expire in 1 hour:

Reset Password: {reset_url}

If you did not request this password reset, please ignore this email.

Best regards,
AuthGuard Team
'''
            
            try:
                if TESTING_MODE:
                    flash(f"Password reset link: {reset_url}", "success")
                    print(f"Reset URL: {reset_url}")
                else:
                    success, message = email_service.send_email(
                        to_email=email,
                        subject='Password Reset Request - AuthGuard',
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
    token_record = db_query_one(
        "SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > ?",
        (token, datetime.datetime.now())
    )
    
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
        
        db_execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, token_record["user_id"]),
            commit=True
        )
        
        db_execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (token_record["id"],),
            commit=True
        )
        
        flash("Password reset successfully! You can now log in with your new password.", "success")
        return redirect(url_for("login"))
    
    return render_template("reset_password.html", token=token)

if __name__ == '__main__':
    app.run(debug=False)
