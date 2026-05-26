-- Land Cruiser Workshop — D1 Database Schema
-- Full schema including all new tables and columns

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    verify_token TEXT,
    reset_token TEXT,
    reset_token_expires INTEGER,
    pending_email TEXT,
    email_change_token TEXT,
    delete_token TEXT,
    delete_token_expires INTEGER,
    series_interest TEXT,
    mailing_list INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch()),
    last_login INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    manual_code TEXT NOT NULL,
    manual_title TEXT,
    downloaded_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    manual_code TEXT NOT NULL,
    manual_title TEXT,
    notes TEXT,
    email TEXT,
    requested_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Alter existing users table to add new columns (safe to run on existing DB)
ALTER TABLE users ADD COLUMN pending_email TEXT;
ALTER TABLE users ADD COLUMN email_change_token TEXT;
ALTER TABLE users ADD COLUMN delete_token TEXT;
ALTER TABLE users ADD COLUMN delete_token_expires INTEGER;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_downloads_user ON downloads(user_id);
CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ts ON rate_limits(timestamp);
CREATE INDEX IF NOT EXISTS idx_manual_requests_code ON manual_requests(manual_code);
