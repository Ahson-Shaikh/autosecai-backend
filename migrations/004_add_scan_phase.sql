-- Migration 004: Add scan_phase column to scans
-- Created: 2024-03-20

-- Check if scans table exists
SELECT name FROM sqlite_master WHERE type='table' AND name='scans';

-- Add scan_phase column if it doesn't exist
ALTER TABLE scans ADD COLUMN scan_phase TEXT; 