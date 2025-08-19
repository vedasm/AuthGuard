import os
from functools import wraps
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, g, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

DATABASE = "password.db"


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
        db = get_db()
        if not username:
            flash("Username is required!", "error")
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
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_pw))
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
