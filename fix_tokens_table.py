"""
Fix the password_reset_tokens table to ensure proper data types
Run this script once to fix any existing issues
"""

import sqlite3
import os

def fix_tokens_table():
    """Recreate the password_reset_tokens table with correct schema"""
    
    # Check if database exists
    if not os.path.exists('password.db'):
        print("❌ Database file 'password.db' not found!")
        return
    
    conn = sqlite3.connect('password.db')
    cursor = conn.cursor()
    
    try:
        print("🔧 Fixing password_reset_tokens table...")
        
        # Drop the existing table
        cursor.execute("DROP TABLE IF EXISTS password_reset_tokens")
        
        # Create the table with correct schema
        cursor.execute('''
            CREATE TABLE password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # Create index for faster token lookups
        cursor.execute('''
            CREATE INDEX idx_token ON password_reset_tokens(token)
        ''')
        
        cursor.execute('''
            CREATE INDEX idx_user_token ON password_reset_tokens(user_id, used)
        ''')
        
        conn.commit()
        print("✅ Password reset tokens table fixed successfully!")
        print("✅ Indexes created for better performance!")
        
        # Verify the schema
        cursor.execute("PRAGMA table_info(password_reset_tokens)")
        columns = cursor.fetchall()
        print("\n📋 Table Schema:")
        for col in columns:
            print(f"   - {col[1]}: {col[2]}")
        
    except Exception as e:
        print(f"❌ Error fixing table: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Password Reset Tokens Table Fix")
    print("=" * 60)
    fix_tokens_table()
    print("\n✨ Done! You can now test the password reset functionality.")
    print("=" * 60)
