# 🔐 AuthGuard - Secure Password Manager

A modern, beautiful password manager built with Python Flask. Store, manage, and retrieve your passwords securely with an elegant user interface.

---

## 📸 Features Overview

| Feature | Description |
|---------|-------------|
| 🔑 **Secure Authentication** | Register, login, password reset via email |
| 🏠 **Encrypted Vault** | Store unlimited account credentials |
| 👁️ **View/Hide Passwords** | Toggle password visibility with one click |
| 📋 **Manage Credentials** | Add, edit, delete your saved passwords |
| 🔒 **Account Security** | Change password, update email, delete account |
| 📱 **Responsive Design** | Works beautifully on desktop, tablet, mobile |
| 🎨 **Modern UI** | Gradient backgrounds, smooth animations, glass morphism |

---

## 🛠️ Technology Stack

```
Backend              Frontend              Database             Deployment
├─ Python 3.8+      ├─ HTML5              ├─ SQLite (Dev)      └─ Vercel
├─ Flask 3.0.3      ├─ CSS3               ├─ PostgreSQL (Prod) 
├─ Werkzeug         ├─ JavaScript         └─ SQLAlchemy ORM
├─ Flask-Session    ├─ Bootstrap 5
└─ Flask-Mail       └─ Material Icons
```

---

## 📦 Installation

### 1️⃣ Clone Repository
```bash
git clone https://github.com/vedasm/authguard.git
cd authguard
```

### 2️⃣ Create Virtual Environment
```bash
python -m venv venv
```

### 3️⃣ Activate Virtual Environment

**Windows:**
```bash
venv\Scripts\activate
```

**macOS/Linux:**
```bash
source venv/bin/activate
```

### 4️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 5️⃣ Configure Environment Variables

Create `environment.txt`:
```
SECRET_KEY=your-secret-key-here-min-32-chars
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-16-char-app-password
TESTING_MODE=False
```

### 6️⃣ Initialize Database
```bash
python init_db.py
```

### 7️⃣ Run Application
```bash
python app.py
```

**Access at:** `http://localhost:5000`

---

## 🌐 Deploy to Vercel

### Prerequisites
- Vercel account
- PostgreSQL database
- GitHub account

### Deployment Steps

1. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Ready for deployment"
   git push origin main
   ```

2. **Connect to Vercel:**
   - Visit [vercel.com](https://vercel.com)
   - Click "New Project"
   - Import your GitHub repository
   - Select Python runtime

3. **Add Environment Variables:**
   
   In Vercel dashboard → Settings → Environment Variables:
   ```
   DATABASE_URL = postgresql://user:pass@host/db
   SECRET_KEY = your-32-char-secret-key
   MAIL_USERNAME = your-email@gmail.com
   MAIL_PASSWORD = your-app-password
   TESTING_MODE = False
   ```

4. **Deploy:**
   ```bash
   Vercel automatically deploys on push to main
   ```

---

## 📧 Email Setup (Gmail)

### Step 1: Enable 2-Factor Authentication
- Go to [Google Account](https://myaccount.google.com)
- Security → 2-Step Verification
- Complete the setup

### Step 2: Generate App Password
- [App Passwords](https://myaccount.google.com/apppasswords)
- Select: Mail → Windows/Linux/Mac
- Copy the 16-character password

### Step 3: Add to Environment
```
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=paste-16-char-password-here
```

---

## 📁 Project Structure

```
authguard/
│
├── app.py                    ← Main Flask app
├── init_db.py               ← Database setup
├── email_service.py         ← Email handler
├── requirements.txt         ← Dependencies
├── environment.txt          ← Local config (create this)
├── vercel.json             ← Vercel config
│
├── static/
│   ├── style.css           ← Global styles
│   └── favicon.svg         ← App icon
│
├── templates/
│   ├── base.html           ← Base layout
│   ├── register.html       ← Sign up
│   ├── login.html          ← Sign in
│   ├── forgot.html         ← Password recovery
│   ├── reset_password.html ← Reset form
│   ├── vault.html          ← Main dashboard
│   ├── add.html            ← Add credential
│   ├── update.html         ← Edit credential
│   └── account.html        ← Settings
│
└── LICENSE
```

---

## 🔐 Security Features

✅ **Password Hashing** - Werkzeug bcrypt encryption  
✅ **CSRF Protection** - Flask built-in defense  
✅ **SQL Injection Prevention** - Parameterized queries  
✅ **Secure Sessions** - Server-side storage  
✅ **Token Expiration** - Password reset in 1 hour  
✅ **HTTPS Ready** - Secure cookies for production  
✅ **Email Verification** - Secure token-based recovery  

---

## 🎨 Design Features

| Feature | Description |
|---------|-------------|
| 🌈 **Gradients** | Beautiful purple-to-pink color scheme |
| ✨ **Animations** | Smooth transitions and slide-in effects |
| 🔵 **Glass Morphism** | Modern frosted glass navbar effect |
| 📱 **Responsive** | Mobile-first design approach |
| ♿ **Accessible** | ARIA labels and semantic HTML |
| 🎯 **Modern Icons** | Google Material Symbols throughout |

---

## 📱 Browser Support

| Browser | Status |
|---------|--------|
| Chrome/Edge | ✅ Latest |
| Firefox | ✅ Latest |
| Safari | ✅ Latest |
| Mobile (iOS/Android) | ✅ Full support |

---

## 🚀 Usage Guide

### Create Account
1. Click "Register"
2. Enter username, email, password
3. Confirm password
4. Click "Create Account"

### Add Password
1. Go to "Add" button
2. Enter website, username, password
3. Click "Add Credential"

### View Saved Passwords
1. Dashboard shows all credentials in table
2. Click eye icon to show/hide password
3. Click copy icon to copy password

### Edit Credential
1. Click edit (pencil icon) on credential
2. Update username or password
3. Click "Update Credential"

### Delete Credential
1. Click delete (trash icon)
2. Confirm deletion
3. Credential removed

### Change Password
1. Go to "Account"
2. Enter current & new password
3. Click "Update Password"

### Reset Forgotten Password
1. On login, click "Forgot password?"
2. Enter email address
3. Check email for reset link
4. Click link and create new password

---

## 🐛 Troubleshooting

### Issue: Database error on startup
**Solution:**
```bash
python init_db.py
python app.py
```

### Issue: Email not sending
**Check:**
- MAIL_USERNAME and MAIL_PASSWORD correct
- Gmail 2FA enabled
- App-specific password used (not Gmail password)
- TESTING_MODE=True for debugging

### Issue: Port 5000 already in use
**Solution:**
```bash
python app.py --port 5001
```

### Issue: Flash messages appearing twice
**Solution:** Remove inline flash message containers from individual templates

---

## 📝 Dependencies

```txt
Flask==3.0.3
Flask-Session==0.5.0
Werkzeug==3.0.1
gunicorn==23.0.0
Flask-Mail==0.9.1
yagmail==0.15.293
python-dotenv==1.0.0
psycopg2-binary==2.9.9
```
---
## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/NewFeature`
3. Commit: `git commit -m 'Add NewFeature'`
4. Push: `git push origin feature/NewFeature`
5. Open Pull Request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

```
Copyright (c) 2025 Veda S M

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 👤 Author

**Veda S M**

[![GitHub](https://img.shields.io/badge/GitHub-vedasm-181717?style=flat-square&logo=github)](https://github.com/vedasm)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-vedasm-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/vedasm/)

---

## ⭐ Support

If AuthGuard helps you, please:
- Star this repository ⭐
- Share with others 📢
- Report issues 🐛

---

**Made with ❤️ for secure password management**

*Last Updated: October 2025*
