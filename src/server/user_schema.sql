-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    auth_hash TEXT NOT NULL,
    wrapped_vault_key BLOB NOT NULL,
    kek_salt BLOB NOT NULL,
    auth_salt BLOB NOT NULL,
    nonce_wvk BLOB NOT NULL,
    
    -- Follow-up features
    -- public_key BLOB,
    -- wrapped_private_key BLOB,
    -- nonce_private_key BLOB,
    -- totp_secret TEXT,
    -- totp_enabled BOOLEAN DEFAULT 0,
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Secrets table
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    -- folder_id INTEGER,              -- Optional relation to a folders table
    
    -- Encrypted content
    name_encrypted BLOB NOT NULL,
    url_encrypted BLOB NOT NULL,
    username_encrypted BLOB NOT NULL,
    password_encrypted BLOB NOT NULL,
    notes_encrypted BLOB NOT NULL,
    
    -- Nonces needed to decrypt the content
    nonce_name BLOB NOT NULL,
    nonce_url BLOB NOT NULL,
    nonce_username BLOB NOT NULL,
    nonce_password BLOB NOT NULL,
    nonce_notes BLOB NOT NULL,
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    -- a folders table will require a foreign key for folder_id
);

-- Indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);
