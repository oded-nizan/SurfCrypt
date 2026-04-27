-- Url cache/history table
CREATE TABLE IF NOT EXISTS url_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    rating INTEGER NOT NULL,
    recommendation TEXT NOT NULL,
    is_shortened BOOLEAN DEFAULT FALSE,
    expanded_url TEXT,
    analysis_data TEXT NOT NULL,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
