const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

// Database path
const dbPath = './users.db';

// Migration paths
const migrationsDir = path.join(__dirname, 'migrations');
const schemaVersionsPath = path.join(migrationsDir, 'schema_versions.json');

// Initialize database
const db = new sqlite3.Database(dbPath);

// Initialize migrations table if it doesn't exist
function initMigrationsTable() {
  return new Promise((resolve, reject) => {
    db.run(`
      CREATE TABLE IF NOT EXISTS db_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        migration_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) {
        console.error('Error creating migrations table:', err.message);
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

// Get current schema version from database
function getCurrentSchemaVersion() {
  return new Promise((resolve, reject) => {
    db.get('SELECT MAX(migration_id) as version FROM db_migrations', (err, row) => {
      if (err) {
        console.error('Error getting schema version:', err.message);
        reject(err);
      } else {
        resolve(row ? row.version || 0 : 0);
      }
    });
  });
}

// Get migrations that need to be applied
function getMigrationsToApply(currentVersion, targetVersion) {
  try {
    // Read schema versions file
    const schemaVersions = JSON.parse(fs.readFileSync(schemaVersionsPath, 'utf8'));
    
    // Filter migrations that need to be applied
    return schemaVersions.migrations
      .filter(migration => migration.id > currentVersion && migration.id <= targetVersion)
      .sort((a, b) => a.id - b.id);
  } catch (error) {
    console.error('Error reading schema versions file:', error.message);
    return [];
  }
}

// Apply a single migration
function applyMigration(migration) {
  return new Promise((resolve, reject) => {
    const migrationPath = path.join(migrationsDir, migration.name);
    
    try {
      // Read migration SQL
      const sql = fs.readFileSync(migrationPath, 'utf8');
      
      // Run migration in a transaction
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        
        // Split SQL by semicolons to handle multiple statements
        const statements = sql.split(';').filter(stmt => stmt.trim());
        
        try {
          // Execute each statement
          for (const statement of statements) {
            if (statement.trim()) {
              db.run(statement.trim());
            }
          }
          
          // Record migration in db_migrations table
          db.run(
            'INSERT INTO db_migrations (migration_id, name) VALUES (?, ?)',
            [migration.id, migration.name]
          );
          
          db.run('COMMIT', () => {
            console.log(`Applied migration: ${migration.name}`);
            resolve();
          });
        } catch (error) {
          db.run('ROLLBACK');
          console.error(`Error applying migration ${migration.name}:`, error.message);
          reject(error);
        }
      });
    } catch (error) {
      console.error(`Error reading migration file ${migration.name}:`, error.message);
      reject(error);
    }
  });
}

// Run all pending migrations
async function runMigrations() {
  try {
    // Initialize migrations table
    await initMigrationsTable();
    
    // Get current schema version
    const currentVersion = await getCurrentSchemaVersion();
    console.log(`Current database schema version: ${currentVersion}`);
    
    // Read target version from schema_versions.json
    const schemaVersions = JSON.parse(fs.readFileSync(schemaVersionsPath, 'utf8'));
    const targetVersion = schemaVersions.current_version;
    
    if (currentVersion < targetVersion) {
      console.log(`Updating schema from version ${currentVersion} to ${targetVersion}`);
      
      // Get migrations to apply
      const migrationsToApply = getMigrationsToApply(currentVersion, targetVersion);
      
      // Apply migrations sequentially
      for (const migration of migrationsToApply) {
        console.log(`Applying migration ${migration.id}: ${migration.name}`);
        await applyMigration(migration);
      }
      
      console.log(`Database schema updated to version ${targetVersion}`);
    } else {
      console.log('Database schema is up to date.');
    }
  } catch (error) {
    console.error('Error running migrations:', error.message);
  }
}

// Export the database connection and functions
module.exports = {
  db,
  runMigrations
}; 