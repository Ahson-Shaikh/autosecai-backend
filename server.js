require("dotenv").config();
const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();

// Import route modules
const authRoutes = require("./routes/auth");
const githubAuthRoutes = require("./routes/oauth/github");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());

// Connect to SQLite
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
  } else {
    console.log("Connected to SQLite database.");
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`
    );
  }
});

// Attach the DB to request objects so routes can use it
app.use((req, res, next) => {
  req.db = db;
  next();
});

// Use routes
app.use("/", authRoutes);          // for /register, /login
app.use("/auth/github", githubAuthRoutes);  // for GitHub OAuth

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
