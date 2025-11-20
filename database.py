import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            status_code INTEGER,
            headers TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            zap_results TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Add zap_results column if it doesn't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE scans ADD COLUMN zap_results TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create settings table for ZAP configuration
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Initialize default ZAP settings if not exists
    default_settings = [
        ('zap_proxy_url', 'http://127.0.0.1:8080'),
        ('zap_api_key', ''),
        ('zap_auto_start', 'true'),
        ('zap_enabled', 'true'),
        ('openai_api_key', ''),
        ('openai_enabled', 'false'),
        ('openai_model', 'gpt-4'),
        ('openai_temperature', '0.7')
    ]
    
    for key, value in default_settings:
        cursor.execute('SELECT * FROM settings WHERE setting_key = ?', (key,))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO settings (setting_key, setting_value)
                VALUES (?, ?)
            ''', (key, value))
    
    # Create default admin user if not exists
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        admin_password = generate_password_hash('admin123')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, is_admin)
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin@cybershield.ai', admin_password, 1))
    
    conn.commit()
    conn.close()

def add_scan_result(url, status_code, headers, user_id=None, zap_results=None):
    """Add a scan result to the database with error handling"""
    conn = None
    try:
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        
        # Validate inputs
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
        
        if status_code is None or not isinstance(status_code, int):
            raise ValueError("Status code must be an integer")
        
        # Serialize zap_results safely
        zap_results_json = None
        if zap_results:
            try:
                zap_results_json = json.dumps(zap_results)
            except (TypeError, ValueError) as e:
                # If JSON serialization fails, store None
                zap_results_json = None
        
        # Serialize headers safely
        headers_str = str(headers) if headers else '{}'
        if len(headers_str) > 10000:  # Limit header size
            headers_str = str(headers)[:10000]
        
        cursor.execute('''
            INSERT INTO scans (url, status_code, headers, user_id, zap_results)
            VALUES (?, ?, ?, ?, ?)
        ''', (url[:2048], status_code, headers_str, user_id, zap_results_json))
        
        scan_id = cursor.lastrowid
        conn.commit()
        return scan_id
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        raise Exception(f"Database error: {str(e)}")
    except Exception as e:
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def get_scan_results(user_id=None):
    """Retrieve scan results for a specific user or all results with error handling"""
    conn = None
    try:
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        
        if user_id:
            if not isinstance(user_id, int) or user_id <= 0:
                return []
            cursor.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY scan_date DESC', (user_id,))
        else:
            cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC')
        
        results = cursor.fetchall()
        return results if results else []
    except sqlite3.Error as e:
        print(f"Database error in get_scan_results: {str(e)}")
        return []
    except Exception as e:
        print(f"Error in get_scan_results: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()

def create_user(username, email, password, is_admin=0):
    """Create a new user with enhanced validation"""
    conn = None
    try:
        # Validate inputs
        if not username or not email or not password:
            return None
        
        if len(username) > 30 or len(email) > 100:
            return None
        
        conn = sqlite3.connect('cybershield.db')
        cursor = conn.cursor()
        
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, is_admin)
            VALUES (?, ?, ?, ?)
        ''', (username[:30], email[:100], password_hash, 1 if is_admin else 0))
        
        user_id = cursor.lastrowid
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        return None
    except Exception as e:
        print(f"Error creating user: {str(e)}")
        return None
    finally:
        if conn:
            conn.close()

def get_user_by_username(username):
    """Get user by username"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    conn.close()
    return user

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    conn.close()
    return user

def verify_password(username, password):
    """Verify user password"""
    user = get_user_by_username(username)
    if user and check_password_hash(user[3], password):
        return user
    return None

def get_all_users():
    """Get all users for admin dashboard"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    
    conn.close()
    return users

def get_setting(setting_key, default_value=None):
    """Get a setting value from database"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT setting_value FROM settings WHERE setting_key = ?', (setting_key,))
    result = cursor.fetchone()
    
    conn.close()
    return result[0] if result else default_value

def update_setting(setting_key, setting_value):
    """Update or create a setting"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (setting_key, setting_value))
    
    conn.commit()
    conn.close()
    return True

def get_all_settings():
    """Get all settings as a dictionary"""
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT setting_key, setting_value FROM settings')
    results = cursor.fetchall()
    
    conn.close()
    return {key: value for key, value in results}

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")