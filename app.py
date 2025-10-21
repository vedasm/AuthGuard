import os
import secrets
import datetime
from functools import wraps
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, g, url_for
from flask_session import Session
from flask_mail import Mail
from werkzeug.security import check_password_hash, generate_password_hash
from email_service import email_service
from dotenv import load_dotenv

# Detect if running on Vercel
IS_VERCEL = bool(os.environ.get('VERCEL'))

# Load .env only locally
try:
    if not IS_VERCEL:
        load_dotenv('environment.txt')
except ImportError:
    pass

app = Flask(__name__)

# Secret key
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("⚠️ Using generated SECRET_KEY. Set SECRET_KEY in Vercel environment variables.")

app.config['SECRET_KEY'] = SECRET_KEY
app.config["SESSION_PERMANENT"] = False

# Session config
if not IS_VERCEL:
    app.config["SESSION_TYPE"] = "filesystem"
    Session(app)
else:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_HTTPONLY'] = True

# Email config
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
TESTING_MODE = os.environ.get('TESTING_MODE', 'False') == 'True'

if not MAIL_USERNAME or not MAIL_PASSWORD:
    print("⚠️ MAIL_USERNAME or MAIL_PASSWORD not set. Email may not work.")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_USERNAME

mail = Mail(app)

# Database setup
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///password.db')

def _is_postgres(url: str) -> bool:
    return url.startswith('postgres://') or url.startswith('postgresql://')

IS_POSTGRES = _is_postgres(DATABASE_URL)
DATABASE = DATABASE_URL if IS_POSTGRES else "password.db"

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
    get_db().commit()

def db_query_one(query, params=()):
    cur = db_execute(query, params)
    return cur.fetchone()

def db_query_all(query, params=()):
    cur = db_execute(query, params)
    return cur.fetchall()

# Initialize DB
try:
    from init_db import init_sqlite_db, init_postgresql_db
    if IS_POSTGRES:
        init_postgresql_db()
    else:
        init_sqlite_db()
except Exception as e:
    print(f"Database init skipped: {e}")

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
        g.user = db_query_one("SELECT * FROM users WHERE id = ?", (user_id,))

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

# ---------------- AUTH ROUTES ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password required!", "error")
            return redirect(url_for("login"))

        row = db_query_one("SELECT * FROM users WHERE username = ?", (username,))
        if row is None or not check_password_hash(row["password_hash"], password):
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

        session["user_id"] = row["id"]
        return redirect("/")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not email or not password or not confirmation:
            flash("All fields are required!", "error")
            return redirect(url_for("register"))
        if password != confirmation:
            flash("Passwords do not match!", "error")
            return redirect(url_for("register"))

        # Unique check
        if db_query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
            flash("Username already taken!", "error")
            return redirect(url_for("register"))
        if db_query_one("SELECT 1 FROM users WHERE email = ?", (email,)):
            flash("Email already registered!", "error")
            return redirect(url_for("register"))

        hash_pw = generate_password_hash(password)
        db_execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                   (username, email, hash_pw), commit=True)

        row = db_query_one("SELECT * FROM users WHERE username = ?", (username,))
        session["user_id"] = row["id"]
        return redirect("/")
    return render_template("register.html")

@app.route("/")
@login_required
def vault():
    credentials = db_query_all("SELECT * FROM credentials WHERE user_id = ?", (g.user["id"],))
    return render_template("vault.html", credentials=credentials)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- CREDENTIAL ROUTES ----------------

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

        db_execute("INSERT INTO credentials (user_id, website, username, password_encrypted) VALUES (?, ?, ?, ?)",
                   (g.user["id"], website, username, password), commit=True)

        flash("Credential added!", "success")
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
                flash("Old password is incorrect", "error")
                return redirect(url_for("account"))

            db_execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(new_password), g.user["id"]), commit=True)
            flash("Password updated!", "success")
            return redirect(url_for("account"))

        elif "change_email" in request.form:
            new_email = request.form.get("new_email")
            if not new_email:
                flash("Email required!", "error")
                return redirect(url_for("account"))
            if db_query_one("SELECT 1 FROM users WHERE email = ?", (new_email,)):
                flash("Email already used!", "error")
                return redirect(url_for("account"))

            db_execute("UPDATE users SET email = ? WHERE id = ?", (new_email, g.user["id"]), commit=True)
            flash("Email updated!", "success")
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
    cred = db_query_one("SELECT * FROM credentials WHERE id = ? AND user_id = ?", (cred_id, g.user["id"]))
    if not cred:
        flash("Credential not found!", "error")
        return redirect(url_for("vault"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("All fields required!", "error")
            return redirect(url_for("update_credential", cred_id=cred_id))

        db_execute("UPDATE credentials SET username = ?, password_encrypted = ? WHERE id = ?",
                   (username, password, cred_id), commit=True)
        flash("Updated successfully!", "success")
        return redirect(url_for("vault"))

    return render_template("update.html", cred=cred)

@app.route("/delete/<int:cred_id>", methods=["POST"])
@login_required
def delete_credential(cred_id):
    db_execute("DELETE FROM credentials WHERE id = ? AND user_id = ?", (cred_id, g.user["id"]), commit=True)
    flash("Credential deleted!", "success")
    return redirect(url_for("vault"))

# ---------------- PASSWORD RESET ----------------

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
            
            # Format datetime as string for SQLite compatibility
            expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')
            
            # Delete any old unused tokens for this user
            try:
                db_execute("DELETE FROM password_reset_tokens WHERE user_id = ? AND used = 0", 
                          (user["id"],), commit=True)
            except:
                pass
            
            db_execute("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                       (user["id"], token, expires_at_str), commit=True)
            
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # ALWAYS show the link if in testing mode
            if TESTING_MODE:
                flash(f"Testing Mode: Copy this reset link", "info")
                flash(reset_url, "success")
                print(f"\n{'='*60}")
                print(f"PASSWORD RESET LINK:")
                print(reset_url)
                print(f"{'='*60}\n")
                return redirect(url_for("forgot"))
            
            # Try to send email only if NOT in testing mode
            msg_body = f'''
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
                        <p>You have requested to reset your password for <strong>AuthGuard</strong>.</p>
                        <p>Click the button below to reset your password. This link will expire in <strong>1 hour</strong>:</p>
                        <a href="{reset_url}" class="button">Reset Password</a>
                        <p>If you did not request this password reset, please ignore this email.</p>
                        <div class="footer">
                            Best regards,<br>
                            <strong>AuthGuard Team</strong>
                        </div>
                    </div>
                </body>
                </html>
                '''
            
            try:
                # Try yagmail first
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
                    # If yagmail fails, show the link as fallback
                    flash(f"Email sending failed. Here's your reset link:", "error")
                    flash(reset_url, "info")
                    print(f"\n{'='*60}")
                    print(f"EMAIL FAILED - PASSWORD RESET LINK:")
                    print(reset_url)
                    print(f"Error: {message}")
                    print(f"{'='*60}\n")
                        
            except Exception as e:
                flash("Failed to send email. Here's your reset link:", "error")
                flash(reset_url, "info")
                print(f"\n{'='*60}")
                print(f"EMAIL ERROR - PASSWORD RESET LINK:")
                print(reset_url)
                print(f"Exception: {str(e)}")
                print(f"{'='*60}\n")
        else:
            # For security, don't reveal if email exists or not
            flash("If an account exists with that email, a reset link has been sent.", "info")
        
        return redirect(url_for("forgot"))
        
    return render_template("forgot.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        # Query token - don't check expiration in the query
        token_record = db_query_one(
            "SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0",
            (token,)
        )

        if not token_record:
            flash("Invalid or already used reset token!", "error")
            return redirect(url_for("login"))
        
        # Check if token is expired
        expires_at = token_record["expires_at"]
        current_time = datetime.datetime.now()
        
        # Handle different datetime formats
        if isinstance(expires_at, str):
            # Try different datetime formats
            try:
                # Format: 2024-01-01 12:00:00
                expires_at = datetime.datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                try:
                    expires_at = datetime.datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    try:
                        # ISO format
                        expires_at = datetime.datetime.fromisoformat(expires_at.replace('Z', ''))
                    except ValueError:
                        flash("Invalid token format!", "error")
                        return redirect(url_for("forgot"))
        
        # Check expiration
        if current_time > expires_at:
            flash("This reset link has expired. Please request a new one.", "error")
            return redirect(url_for("forgot"))

        if request.method == "POST":
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            if not new_password or not confirm_password:
                flash("All fields are required!", "error")
                return redirect(url_for("reset_password", token=token))

            if new_password != confirm_password:
                flash("Passwords do not match!", "error")
                return redirect(url_for("reset_password", token=token))

            try:
                # Update password
                new_hash = generate_password_hash(new_password)
                db_execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_hash, token_record["user_id"]),
                    commit=True
                )
                
                # Mark token as used
                db_execute(
                    "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
                    (token_record["id"],),
                    commit=True
                )
                
                flash("Password reset successfully! You can now log in with your new password.", "success")
                return redirect(url_for("login"))
                
            except Exception as e:
                flash(f"Error updating password: {str(e)}", "error")
                return redirect(url_for("reset_password", token=token))

        return render_template("reset_password.html", token=token)
        
    except Exception as e:
        print(f"Error in reset_password route: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"Error processing reset request. Please try requesting a new reset link.", "error")
        return redirect(url_for("forgot"))


if __name__ == '__main__':
    app.run(debug=False)
