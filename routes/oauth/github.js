// routes/oauth/github.js
const express = require("express");
const axios = require("axios");
const querystring = require("querystring");
const jwt = require("jsonwebtoken");

const router = express.Router();

const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173"; // Updated to use Vite default port
const JWT_SECRET = process.env.JWT_SECRET || "secret";

// 1) GET /auth/github/
//    Redirect user to GitHub for authentication
router.get("/", (req, res) => {
  console.log("Redirecting to GitHub OAuth with CLIENT_ID:", CLIENT_ID);
  const githubAuthUrl =
    "https://github.com/login/oauth/authorize?" +
    querystring.stringify({
      client_id: CLIENT_ID,
      scope: "repo user", // Expanded scope to include user info
      redirect_uri: `${process.env.BACKEND_URL || "http://localhost:3000"}/auth/github/callback`,
    });

  return res.redirect(githubAuthUrl);
});

// 2) GitHub redirects here with ?code=....
router.get("/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).json({ error: "Missing code from GitHub" });
  }

  try {
    console.log("Received code from GitHub, exchanging for token");
    // Exchange code for an access token
    const tokenRes = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
      },
      { headers: { Accept: "application/json" } }
    );

    const accessToken = tokenRes.data.access_token;
    if (!accessToken) {
      console.error("No access token received from GitHub");
      return res.status(400).json({ error: "No access token received from GitHub" });
    }

    console.log("Access token received, getting user info");
    // Get GitHub user info
    const userResponse = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `token ${accessToken}` }
    });
    
    const githubUser = userResponse.data;
    console.log("GitHub user info received:", githubUser.login);
    const db = req.db;
    
    // Check if user exists in our database
    db.get(`SELECT * FROM users WHERE github_id = ?`, [githubUser.id], async (err, user) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }
      
      let userId;
      
      if (!user) {
        console.log("Creating new user for GitHub user:", githubUser.login);
        // Create new user if doesn't exist
        db.run(
          `INSERT INTO users (username, email, github_id, github_token) VALUES (?, ?, ?, ?)`,
          [githubUser.login, githubUser.email || `${githubUser.login}@github.com`, githubUser.id, accessToken],
          function(err) {
            if (err) {
              console.error("Error creating user:", err);
              return res.status(500).json({ error: "Error creating user" });
            }
            userId = this.lastID;
            createTokenAndRedirect(userId, githubUser.login);
          }
        );
      } else {
        console.log("Updating GitHub token for existing user:", user.username);
        // Update existing user's GitHub token
        db.run(
          `UPDATE users SET github_token = ? WHERE id = ?`,
          [accessToken, user.id],
          function(err) {
            if (err) {
              console.error("Error updating user:", err);
              return res.status(500).json({ error: "Error updating user" });
            }
            userId = user.id;
            createTokenAndRedirect(userId, user.username);
          }
        );
      }
      
      function createTokenAndRedirect(userId, username) {
        // Create JWT token for our app - store both userId and githubToken
        const token = jwt.sign(
          { id: userId, username: username, githubToken: accessToken },
          JWT_SECRET,
          { expiresIn: "24h" }
        );
        
        console.log("Redirecting to frontend with token");
        // Redirect to frontend with token
        return res.redirect(`${FRONTEND_URL}/home?token=${token}`);
      }
    });
  } catch (error) {
    console.error("GitHub OAuth error:", error.message);
    if (error.response) {
      console.error("Response data:", error.response.data);
      console.error("Response status:", error.response.status);
    }
    return res.status(500).json({ error: "GitHub OAuth error", details: error.message });
  }
});

// 3) Get user repositories
router.get("/repositories", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: "Authentication required" });
    }
    
    const token = authHeader.split(' ')[1];
    let decoded;
    
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtError) {
      console.error("JWT verification error:", jwtError);
      return res.status(401).json({ error: "Invalid token" });
    }
    
    if (!decoded.id) {
      return res.status(400).json({ error: "Invalid token format - missing user ID" });
    }
    
    // Retrieve the GitHub token from the database rather than the JWT
    const db = req.db;
    db.get(`SELECT github_token FROM users WHERE id = ?`, [decoded.id], async (err, user) => {
      if (err || !user || !user.github_token) {
        console.error("Error retrieving GitHub token:", err || "No token found");
        return res.status(401).json({ error: "GitHub authentication required" });
      }
      
      const githubToken = user.github_token;
      
      try {
        console.log(`Fetching repositories for user ID ${decoded.id} with GitHub token`);
        // Get GitHub repositories
        const reposResponse = await axios.get('https://api.github.com/user/repos', {
          headers: { 
            Authorization: `token ${githubToken}`,
            Accept: 'application/vnd.github.v3+json'
          },
          params: {
            sort: 'updated',
            per_page: 100
          }
        });
        
        const repositories = reposResponse.data.map(repo => ({
          id: repo.id,
          name: repo.name,
          url: repo.html_url,
          description: repo.description || '',
          language: repo.language,
          owner: repo.owner.login,
          isPrivate: repo.private,
          updatedAt: repo.updated_at
        }));
        
        return res.json({ repositories });
      } catch (error) {
        console.error("Error fetching GitHub repositories:", error.message);
        if (error.response) {
          console.error("Response data:", error.response.data);
          console.error("Response status:", error.response.status);
        }
        return res.status(500).json({ 
          error: "Error fetching repositories", 
          details: error.message,
          githubError: error.response?.data
        });
      }
    });
  } catch (error) {
    console.error("General error in repositories endpoint:", error);
    return res.status(500).json({ error: "Error fetching repositories" });
  }
});

// Debug endpoint to check GitHub token
router.get("/checktoken", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: "Authentication required" });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const db = req.db;
    db.get(`SELECT username, github_token FROM users WHERE id = ?`, [decoded.id], (err, user) => {
      if (err) {
        return res.status(500).json({ error: "Database error" });
      }
      
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      
      return res.json({ 
        message: "Token info", 
        username: user.username,
        hasGithubToken: !!user.github_token,
        tokenFirstChars: user.github_token ? user.github_token.substring(0, 5) + '...' : null
      });
    });
  } catch (error) {
    console.error("Token check error:", error);
    return res.status(500).json({ error: "Error checking token" });
  }
});

module.exports = router;
