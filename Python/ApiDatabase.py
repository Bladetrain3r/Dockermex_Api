# ApiDatabase.py
"""
ApiDatabase.py

This module provides a DatabaseManager class for managing a SQLite database 
that stores user information and access tokens. It includes methods for 
initializing the database, creating tables, and handling user authentication 
and session management.

Classes:
    DatabaseManager: Manages the SQLite database, including user and access 
    token tables.

Usage:
    db_manager = DatabaseManager('/path/to/database.db')
    db_manager.some_method()

Dependencies:
    - sqlite3
    - hashlib
    - secrets
    - typing
    - logging
    - datetime
"""

import sqlite3
import hashlib
import secrets
from typing import Optional, List, Dict
import logging
from datetime import datetime
import string

logger = logging.getLogger('api_database')

class DatabaseManager:
    STATIC_SALT = "D0ck3rM3x!"  # Constant salt
    PEPPER_SUBSTITUTIONS = str.maketrans(
        string.ascii_letters + string.digits,
        string.ascii_letters[::-1] + string.digits[::-1]
    )

    ROLE_GUEST = 'guest'
    ROLE_USER = 'user'
    ROLE_ADMIN = 'admin'
    
    # Storage limits (in bytes)
    STORAGE_LIMITS = {
        ROLE_GUEST: 0,  # Guests can't upload
        ROLE_USER: 100 * 1024 * 1024,  # 100MB
        ROLE_ADMIN: 0  # Unlimited
    }

    def __init__(self, db_path: str = '/sqlite/users.db'):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database and create tables if they don't exist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        active BOOLEAN DEFAULT 1
                    )
                ''')
                
                # Access tokens table for session management
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS access_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        token TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                # WADs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wads (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        hash TEXT NOT NULL,
                        upload_path TEXT NOT NULL,
                        type TEXT NOT NULL,  -- 'PWAD' or 'IWAD'
                        uploader_id INTEGER,
                        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expiry_date TIMESTAMP,
                        filesize INTEGER NOT NULL,
                        is_commercial BOOLEAN DEFAULT 0,
                        description TEXT,
                        FOREIGN KEY (uploader_id) REFERENCES users (id)
                    )
                ''')
                
                # WAD access permissions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wad_permissions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        wad_id INTEGER,
                        user_id INTEGER,
                        can_read BOOLEAN DEFAULT 1,
                        can_delete BOOLEAN DEFAULT 0,
                        FOREIGN KEY (wad_id) REFERENCES wads (id),
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS configs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        creator_id INTEGER,
                        created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expiry_date TIMESTAMP,
                        wad_id INTEGER,
                        is_permanent BOOLEAN DEFAULT 0,
                        config_data TEXT NOT NULL,
                        FOREIGN KEY (creator_id) REFERENCES users (id),
                        FOREIGN KEY (wad_id) REFERENCES wads (id)
                    )
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

    def add_user(self, username: str, password: str, role: str = 'user') -> bool:
        """Add a new user to the database"""
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (username, password_hash, role)
                )
                conn.commit()
                logger.info(f"User {username} added successfully")
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"User {username} already exists")
            return False
        except sqlite3.Error as e:
            logger.error(f"Error adding user: {e}")
            return False

    def verify_user(self, username: str, password: str) -> Optional[Dict]:
        """Verify user credentials and return user data if valid"""
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, username, role, active
                    FROM users
                    WHERE username = ? AND password_hash = ? AND active = 1
                ''', (username, password_hash))
                
                user = cursor.fetchone()
                
                if user:
                    # Update last login time
                    cursor.execute(
                        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                        (user['id'],)
                    )
                    conn.commit()
                    
                    return dict(user)
                return None
        except sqlite3.Error as e:
            logger.error(f"Error verifying user: {e}")
            return None

    def create_session(self, user_id: int, expires_in: int = 3600) -> Optional[str]:
        """Create a new session token for user"""
        try:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now().timestamp() + expires_in
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO access_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                    (user_id, token, expires_at)
                )
                conn.commit()
                return token
        except sqlite3.Error as e:
            logger.error(f"Error creating session: {e}")
            return None

    def verify_session(self, token: str) -> Optional[Dict]:
        """Verify session token and return user data if valid"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT u.id, u.username, u.role
                    FROM users u
                    JOIN access_tokens t ON u.id = t.user_id
                    WHERE t.token = ? AND t.expires_at > ? AND u.active = 1
                ''', (token, datetime.now().timestamp()))
                
                user = cursor.fetchone()
                return dict(user) if user else None
        except sqlite3.Error as e:
            logger.error(f"Error verifying session: {e}")
            return None

    def invalidate_session(self, token: str) -> bool:
        """Invalidate a session token"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM access_tokens WHERE token = ?', (token,))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Error invalidating session: {e}")
            return False
        
    def get_user(self, user_id: int) -> Optional[Dict]:
        """Get user data by ID (excluding password hash)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT id, username, role, created_at, last_login, active FROM users WHERE id = ?',
                    (user_id,)
                )
                user = cursor.fetchone()
                return dict(user) if user else None
        except sqlite3.Error as e:
            logger.error(f"Error getting user: {e}")
            return None

    def list_users(self) -> List[Dict]:
        """List all users (excluding password hashes)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, role, created_at, last_login, active
                    FROM users
                    ORDER BY username
                ''')
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error("Error listing users: %s", e)
            return []

    def modify_user(self, user_id: int, **kwargs) -> bool:
        """Modify user attributes"""
        allowed_fields = {'username', 'password', 'role', 'active'}
        update_fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if 'password' in update_fields:
            update_fields['password_hash'] = hashlib.sha256(
                update_fields.pop('password').encode()
            ).hexdigest()
        
        if not update_fields:
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                set_clause = ', '.join(f'{k} = ?' for k in update_fields)
                values = tuple(update_fields.values()) + (user_id,)
                
                cursor.execute(
                    f'UPDATE users SET {set_clause} WHERE id = ?',
                    values
                )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error modifying user: {e}")
            return False

    def delete_user(self, user_id: int) -> bool:
        """Delete a user (or set inactive)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Soft delete - just set inactive
                # Todo: Hard delete if already inactive
                cursor.execute(
                    'UPDATE users SET active = 0 WHERE id = ?',
                    (user_id,)
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Error deleting user: {e}")
            return False

    def cleanup_sessions(self) -> int:
        """Clean up expired sessions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'DELETE FROM access_tokens WHERE expires_at < ?',
                    (datetime.now().timestamp(),)
                )
                conn.commit()
                return cursor.rowcount
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up sessions: {e}")
            return 0  
               
    def get_user_storage_usage(self, user_id: int) -> int:
        """Get total storage used by user in bytes"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COALESCE(SUM(filesize), 0)
                    FROM wads
                    WHERE uploader_id = ? AND (expiry_date IS NULL OR expiry_date > CURRENT_TIMESTAMP)
                ''', (user_id,))
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Error getting storage usage: {e}")
            return 0

    def can_upload_file(self, user_id: int, filesize: int) -> bool:
        """Check if user can upload file of given size"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get user role
                cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
                role = cursor.fetchone()[0]
                
                # Admins have no limit
                if role == self.ROLE_ADMIN:
                    return True
                    
                # Guests can't upload
                if role == self.ROLE_GUEST:
                    return False
                
                # Check user's limit
                limit = self.STORAGE_LIMITS.get(role, 0)
                if limit == 0:
                    return False
                    
                current_usage = self.get_user_storage_usage(user_id)
                return (current_usage + filesize) <= limit
                
        except sqlite3.Error as e:
            logger.error(f"Error checking upload capability: {e}")
            return False

    def register_wad(self, filename: str, hash: str, upload_path: str, 
                     wad_type: str, uploader_id: int, filesize: int,
                     description: str = None, is_commercial: bool = False) -> Optional[int]:
        """Register a new WAD with size tracking"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get user role
                cursor.execute('SELECT role FROM users WHERE id = ?', (uploader_id,))
                role = cursor.fetchone()[0]
                
                # Set expiry based on role
                expiry_date = None
                if role == self.ROLE_GUEST:
                    expiry_date = 'datetime("now", "+1 day")'
                elif role == self.ROLE_USER:
                    expiry_date = 'datetime("now", "+7 days")'
                
                cursor.execute('''
                    INSERT INTO wads 
                    (filename, hash, upload_path, type, uploader_id, description, 
                     is_commercial, filesize, expiry_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (filename, hash, upload_path, wad_type, uploader_id, 
                      description, is_commercial, filesize, expiry_date))
                
                wad_id = cursor.lastrowid
                
                # Add default permission
                cursor.execute('''
                    INSERT INTO wad_permissions (wad_id, user_id, can_read, can_delete)
                    VALUES (?, ?, 1, 1)
                ''', (wad_id, uploader_id))
                
                conn.commit()
                return wad_id
                
        except sqlite3.Error as e:
            logger.error(f"Error registering WAD: {e}")
            return None

    def create_config(self, name: str, creator_id: int, config_data: str,
                     wad_id: Optional[int] = None) -> Optional[int]:
        """Create a new configuration"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get creator role
                cursor.execute('SELECT role FROM users WHERE id = ?', (creator_id,))
                role = cursor.fetchone()[0]
                
                # Set permanence and expiry based on role
                is_permanent = (role == self.ROLE_ADMIN)
                expiry_date = None
                if role == self.ROLE_GUEST:
                    expiry_date = 'datetime("now", "+1 day")'
                elif role == self.ROLE_USER:
                    expiry_date = 'datetime("now", "+7 days")'
                
                cursor.execute('''
                    INSERT INTO configs 
                    (name, creator_id, wad_id, config_data, is_permanent, expiry_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (name, creator_id, wad_id, config_data, is_permanent, expiry_date))
                
                conn.commit()
                return cursor.lastrowid
                
        except sqlite3.Error as e:
            logger.error(f"Error creating config: {e}")
            return None

    def can_access_commercial_wad(self, user_id: int) -> bool:
        """Check if user can access commercial WADs"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
                role = cursor.fetchone()[0]
                return role in (self.ROLE_USER, self.ROLE_ADMIN)
        except sqlite3.Error as e:
            logger.error(f"Error checking commercial WAD access: {e}")
            return False

    def get_active_configs(self, user_id: Optional[int] = None) -> List[Dict]:
        """Get non-expired configurations"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = '''
                    SELECT c.*, u.username as creator_name
                    FROM configs c
                    JOIN users u ON c.creator_id = u.id
                    WHERE (c.expiry_date IS NULL OR c.expiry_date > CURRENT_TIMESTAMP)
                '''
                params = []
                
                if user_id is not None:
                    query += ' AND c.creator_id = ?'
                    params.append(user_id)
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Error getting configs: {e}")
            return []
        
    def get_all_wads(self) -> List[Dict]:
        """Get all WADs with uploader info"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT w.*, u.username as uploader_name
                    FROM wads w
                    JOIN users u ON w.uploader_id = u.id
                    ORDER BY w.upload_date DESC
                ''')
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error getting all WADs: {e}")
            return []
    
    def edit_wad(self, wad_id: int, **kwargs) -> bool:
        """Edit WAD properties"""
        allowed_fields = {'expiry_date', 'description'}
        update_fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not update_fields:
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                set_clause = ', '.join(f'{k} = ?' for k in update_fields)
                values = tuple(update_fields.values()) + (wad_id,)
                cursor.execute(
                    f'UPDATE wads SET {set_clause} WHERE id = ?',
                    values
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Error editing WAD: {e}")
            return False
    
    def edit_config(self, config_id: int, **kwargs) -> bool:
        """Edit configuration properties"""
        allowed_fields = {'expiry_date', 'is_permanent', 'name'}
        update_fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not update_fields:
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                set_clause = ', '.join(f'{k} = ?' for k in update_fields)
                values = tuple(update_fields.values()) + (config_id,)
                cursor.execute(
                    f'UPDATE configs SET {set_clause} WHERE id = ?',
                    values
                )
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Error editing config: {e}")
            return False