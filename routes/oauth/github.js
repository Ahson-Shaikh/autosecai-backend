// routes/oauth/github.js
const express = require("express");
const axios = require("axios");
const querystring = require("querystring");

const router = express.Router();

const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

// 1) GET /auth/github/
//    Redirect user to GitHub for authentication
router.get("/", (req, res) => {
  const githubAuthUrl =
    "https://github.com/login/oauth/authorize?" +
    querystring.stringify({
      client_id: CLIENT_ID,
      scope: "repo", // or whatever scope you need
      redirect_uri: `${FRONTEND_URL}/auth/callback`, 
      // or define a route if you'd prefer your server to handle callback
    });

  return res.redirect(githubAuthUrl);
});

// 2) If you want your server to handle the callback, do GET /auth/github/callback
//    GitHub redirects here with ?code=....
router.get("/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).json({ error: "Missing code from GitHub" });
  }

  try {
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
      return res.status(400).json({ error: "No access token received from GitHub" });
    }

    // Option 1: store the token in DB or session. 
    // Option 2: redirect with the token in the querystring 
    //   (for demonstration only, not recommended in production)
    const redirectUrl = `${FRONTEND_URL}/auth?token=${accessToken}`;
    return res.redirect(redirectUrl);
  } catch (error) {
    console.error("GitHub OAuth error:", error);
    return res.status(500).json({ error: "GitHub OAuth error" });
  }
});

module.exports = router;
