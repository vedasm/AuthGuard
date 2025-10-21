#!/usr/bin/env python3
"""
Database initialization script for AuthGuard
Creates tables for both SQLite (local) and PostgreSQL (production)
"""

import os
import sqlite3

def init_sqlite_db():
    """Initialize SQLite database for local development"""
    conn = sqlite3.connect('password.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # Create credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create password reset tokens table
    # Store expires_at as TEXT (ISO format) to avoid datetime errors in SQLite
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ SQLite database initialized successfully!")


def init_postgresql_db():
    """Initialize PostgreSQL database for production"""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor

        DATABASE_URL = os.environ.get('DATABASE_URL')
        if not DATABASE_URL:
            print("❌ DATABASE_URL not found in environment variables")
            return

        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            )
        ''')

        # Create credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                website VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                password_encrypted TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # Create password reset tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token VARCHAR(255) UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        conn.commit()
        conn.close()
        print("✅ PostgreSQL database initialized successfully!")

    except ImportError:
        print("❌ psycopg2 not installed. Install with: pip install psycopg2-binary")
    except Exception as e:
        print(f"❌ Error initializing PostgreSQL database: {e}")


def main():
    """Initialize database based on environment"""
    print("🔧 Initializing AuthGuard database...")

    if os.environ.get('VERCEL'):
        print("🌐 Production environment detected - initializing PostgreSQL...")
        init_postgresql_db()
    else:
        print("💻 Local environment detected - initializing SQLite...")
        init_sqlite_db()

    print("🎉 Database initialization complete!")


if __name__ == "__main__":
    main()
