require("dotenv").config();
const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const http = require('http');
const socketIO = require('socket.io');

// Import route modules
const authRoutes = require("./routes/auth");
const githubAuthRoutes = require("./routes/oauth/github");
const scanRoutes = require("./routes/scan");
const settingsRoutes = require("./routes/settings/user");

// Import database module
const { db, runMigrations } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Create HTTP server and Socket.IO instance
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Store scan rooms by scan ID
const scanRooms = {};

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // Join a scan room to receive updates about a specific scan
  socket.on('join-scan', (scanId) => {
    console.log(`Client ${socket.id} joined scan room: ${scanId}`);
    socket.join(`scan-${scanId}`);
    scanRooms[socket.id] = `scan-${scanId}`;
  });
  
  // Leave a scan room
  socket.on('leave-scan', () => {
    if (scanRooms[socket.id]) {
      console.log(`Client ${socket.id} left scan room: ${scanRooms[socket.id]}`);
      socket.leave(scanRooms[socket.id]);
      delete scanRooms[socket.id];
    }
  });
  
  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    if (scanRooms[socket.id]) {
      socket.leave(scanRooms[socket.id]);
      delete scanRooms[socket.id];
    }
  });
});

// Make io available to route handlers
app.set('io', io);

// Middleware
app.use(express.json());
app.use(cors());

// Run database migrations before starting server
(async () => {
  try {
    console.log("Running database migrations...");
    await runMigrations();
    console.log("Database migrations completed successfully.");
    
    // Attach the DB to request objects so routes can use it
    app.use((req, res, next) => {
      req.db = db;
      next();
    });
    
    // Use routes
    app.use("/", authRoutes);          // for /register, /login
    app.use("/auth/github", githubAuthRoutes);  // for GitHub OAuth
    app.use("/scan", scanRoutes);      // for scanning repositories
    app.use("/settings", settingsRoutes);  // for user settings
    
    // Start server
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Error during server startup:", error);
    process.exit(1);
  }
})();

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Closing database connection...');
  db.close(() => {
    console.log('Database connection closed.');
    process.exit(0);
  });
});
