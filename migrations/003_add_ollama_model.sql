-- Migration 003: Add ollama_model column to user_settings
-- Created: 2023-10-20

-- Check if user_settings table exists
SELECT name FROM sqlite_master WHERE type='table' AND name='user_settings';

-- Add ollama_model column if it doesn't exist
ALTER TABLE user_settings ADD COLUMN ollama_model TEXT DEFAULT 'llama3'; 