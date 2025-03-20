-- Migration 002: Add user settings table
-- Created: 2023-08-15

-- User settings table - storing AI configuration
CREATE TABLE IF NOT EXISTS user_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  openai_key TEXT,
  openai_iv TEXT,
  ollama_endpoint TEXT,
  ollama_iv TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
); 