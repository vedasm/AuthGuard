# AuthGuard – Password Manager

A password manager built with Python and Flask. Store, manage, and retrieve account credentials through a web interface.

## Features

- User authentication: register, log in, and reset password via email
- Credential vault for storing website / username / password entries
- Show/hide toggle for stored passwords
- Add, edit, and delete saved credentials
- Account settings: change password, update email, delete account
- Responsive layout for desktop, tablet, and mobile
- Built-in password generator with adjustable length and character sets

## Technology Stack

- **Backend:** Python 3.8+, Flask 3.0.3, Flask-Session, Flask-Mail
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5, Material Symbols
- **Database:** SQLite (local), PostgreSQL (production)
- **Deployment:** Vercel

## Installation

1. Clone the repository
   ```bash
   git clone https://github.com/vedasm/authguard.git
   cd authguard
   ```
2. Create and activate a virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```
3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
4. Create an `environment.txt` file:
   ```
   SECRET_KEY=your-secret-key-here-min-32-chars
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-16-char-app-password
   TESTING_MODE=False
   ```
5. Initialize the database
   ```bash
   python init_db.py
   ```
6. Run the app
   ```bash
   python app.py
   ```
   Visit `http://localhost:5000`

## Deploying to Vercel

1. Push the repository to GitHub.
2. In Vercel, create a new project and import the repository (Python runtime).
3. Add environment variables under Vercel → Settings → Environment Variables:
   ```
   DATABASE_URL = postgresql://user:pass@host/db
   SECRET_KEY = your-32-char-secret-key
   MAIL_USERNAME = your-email@gmail.com
   MAIL_PASSWORD = your-app-password
   TESTING_MODE = False
   ```
4. Vercel deploys automatically on every push to `main`.

## Email Setup (Gmail)

1. Enable 2-Step Verification on your Google Account.
2. Generate an [app password](https://myaccount.google.com/apppasswords) for Mail.
3. Set `MAIL_USERNAME` and `MAIL_PASSWORD` (the 16-character app password) in your environment.

## Project Structure

```
authguard/
├── app.py                 Main Flask app
├── init_db.py              Database setup
├── email_service.py        Email handler
├── fix_tokens_table.py     One-off script to repair the token table schema
├── requirements.txt
├── environment.txt         Local config (not committed)
├── vercel.json
├── static/
│   ├── style.css
│   └── favicon.svg
├── templates/
│   ├── base.html
│   ├── register.html
│   ├── login.html
│   ├── forgot.html
│   ├── reset_password.html
│   ├── vault.html
│   ├── add.html
│   ├── update.html
│   └── account.html
└── LICENSE
```

## Security Notes

- User account passwords are hashed with Werkzeug before storage.
- All SQL queries are parameterized.
- Sessions are stored server-side via Flask-Session.
- Password reset tokens expire after 1 hour and are single-use.
- **Stored vault credentials (the website/username/password entries you save) are currently kept in plain text** — the `password_encrypted` column name is aspirational rather than accurate. If this is used for real accounts, add field-level encryption (e.g. `cryptography`'s Fernet) before writing `password` to the database.

## Usage

- **Register:** create a username, email, and password.
- **Add a credential:** go to "Add", enter website / username / password.
- **View a password:** click the eye icon in the vault table.
- **Edit / delete:** use the icons in the Actions column.
- **Change account password or email:** go to "Account".
- **Forgot password:** use the "Forgot password?" link on the login page.

## Troubleshooting

- **Database error on startup:** run `python init_db.py`, then `python app.py`.
- **Email not sending:** confirm `MAIL_USERNAME` / `MAIL_PASSWORD` are correct, 2FA is enabled, and you're using an app password (not your regular Gmail password). Set `TESTING_MODE=True` to print the reset link instead of emailing it.
- **Port 5000 already in use:** run on a different port, e.g. `flask run --port 5001`.

## Dependencies

```
Flask==3.0.3
Flask-Session==0.5.0
Werkzeug==3.0.1
gunicorn==23.0.0
Flask-Mail==0.9.1
yagmail==0.15.293
python-dotenv==1.0.0
psycopg2-binary==2.9.9
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/NewFeature`
3. Commit your changes: `git commit -m 'Add NewFeature'`
4. Push the branch: `git push origin feature/NewFeature`
5. Open a pull request

## License

MIT License — see [LICENSE](LICENSE).

## Author

Veda S M
[GitHub](https://github.com/vedasm) · [LinkedIn](https://linkedin.com/in/vedasm)
