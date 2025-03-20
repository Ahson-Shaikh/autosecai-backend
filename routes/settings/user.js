const express = require("express");
const router = express.Router();
const crypto = require('crypto');
const axios = require("axios");

// Middleware for authenticating JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  
  try {
    const jwt = require("jsonwebtoken");
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token." });
  }
};

// Encryption setup with proper key length
const algorithm = 'aes-256-ctr';
// Create a 32 byte (256 bit) key from the secret
const getEncryptionKey = (secret) => {
  // Use a crypto hash function to create a consistent 32-byte key
  const key = crypto.createHash('sha256').update(String(secret)).digest();
  console.log("Settings encryption - Key first 5 chars:", key.toString('hex').substring(0, 10) + "...");
  return key;
};

// Save user settings (API keys)
router.post("/api-keys", authenticateToken, (req, res) => {
  const { openaiKey, ollamaEndpoint, ollamaModel } = req.body;
  const { id: userId } = req.user;
  const db = req.db;
  
  // Check if settings entry exists for user
  db.get(
    `SELECT * FROM user_settings WHERE user_id = ?`,
    [userId],
    (err, settings) => {
      if (err) {
        console.error("Error checking settings:", err);
        return res.status(500).json({ error: "Database error" });
      }
      
      // Encrypt keys before storing with proper key length
      const secretKey = process.env.SETTINGS_ENCRYPTION_KEY || 'secret-key-for-settings-encryption';
      const encryptionKey = getEncryptionKey(secretKey);
      
      const encrypt = (text) => {
        if (!text) return null;
        
        console.log("Text to encrypt:", text);
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
        const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
        return {
          iv: iv.toString('hex'),
          content: encrypted.toString('hex')
        };
      };
      
      const encryptedOpenAI = encrypt(openaiKey);
      const encryptedOllama = encrypt(ollamaEndpoint);
      
      if (!settings) {
        // Insert new settings
        db.run(
          `INSERT INTO user_settings (user_id, openai_key, openai_iv, ollama_endpoint, ollama_iv, ollama_model, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
          [
            userId, 
            encryptedOpenAI ? encryptedOpenAI.content : null,
            encryptedOpenAI ? encryptedOpenAI.iv : null,
            encryptedOllama ? encryptedOllama.content : null,
            encryptedOllama ? encryptedOllama.iv : null,
            ollamaModel || null
          ],
          function(err) {
            if (err) {
              console.error("Error saving settings:", err);
              return res.status(500).json({ error: "Error saving settings" });
            }
            
            return res.json({ message: "Settings saved successfully" });
          }
        );
      } else {
        // Update existing settings
        db.run(
          `UPDATE user_settings 
           SET openai_key = ?, openai_iv = ?, ollama_endpoint = ?, ollama_iv = ?, ollama_model = ?, updated_at = CURRENT_TIMESTAMP
           WHERE user_id = ?`,
          [
            encryptedOpenAI ? encryptedOpenAI.content : null,
            encryptedOpenAI ? encryptedOpenAI.iv : null,
            encryptedOllama ? encryptedOllama.content : null,
            encryptedOllama ? encryptedOllama.iv : null,
            ollamaModel || settings.ollama_model,
            userId
          ],
          function(err) {
            if (err) {
              console.error("Error updating settings:", err);
              return res.status(500).json({ error: "Error updating settings" });
            }
            
            return res.json({ message: "Settings updated successfully" });
          }
        );
      }
    }
  );
});

// Get user settings (API keys)
router.get("/api-keys", authenticateToken, (req, res) => {
  const { id: userId } = req.user;
  const db = req.db;
  
  db.get(
    `SELECT * FROM user_settings WHERE user_id = ?`,
    [userId],
    (err, settings) => {
      if (err) {
        console.error("Error fetching settings:", err);
        return res.status(500).json({ error: "Database error" });
      }
      
      if (!settings) {
        return res.json({ 
          hasOpenAI: false,
          hasOllama: false,
          ollamaModel: null
        });
      }
      
      // Decrypt keys using the same encryption key generation
      const secretKey = process.env.SETTINGS_ENCRYPTION_KEY || 'secret-key-for-settings-encryption';
      const encryptionKey = getEncryptionKey(secretKey);
      
      const decrypt = (hash, iv) => {
        if (!hash || !iv) return null;
        const decipher = crypto.createDecipheriv(
          algorithm, 
          encryptionKey, 
          Buffer.from(iv, 'hex')
        );
        const decrpyted = Buffer.concat([
          decipher.update(Buffer.from(hash, 'hex')),
          decipher.final()
        ]);
        return decrpyted.toString();
      };
      
      // Only send if keys exist, don't send actual keys for security
      const hasOpenAI = settings.openai_key && settings.openai_iv;
      const hasOllama = settings.ollama_endpoint && settings.ollama_iv;
      
      // Decrypt only for testing connection
      let openaiKey = null;
      let ollamaEndpoint = null;
      
      try {
        if (hasOpenAI) {
          openaiKey = decrypt(settings.openai_key, settings.openai_iv);
        }
        if (hasOllama) {
          ollamaEndpoint = decrypt(settings.ollama_endpoint, settings.ollama_iv);
        }
      } catch (err) {
        console.error("Error decrypting settings:", err);
      }
      
      return res.json({
        hasOpenAI,
        hasOllama,
        // For testing connection, decrypt and send values
        openaiKey,
        ollamaEndpoint,
        ollamaModel: settings.ollama_model
      });
    }
  );
});

// Get available Ollama models
router.post("/ollama-models", authenticateToken, async (req, res) => {
  const { ollamaEndpoint } = req.body;
  
  if (!ollamaEndpoint) {
    return res.status(400).json({ 
      error: "Ollama endpoint is required",
      success: false
    });
  }
  
  // Validate and normalize the URL
  let endpoint;
  try {
    // Make sure the URL has a protocol
    if (!ollamaEndpoint.startsWith('http://') && !ollamaEndpoint.startsWith('https://')) {
      endpoint = `http://${ollamaEndpoint}`;
      console.log("Added protocol to Ollama endpoint:", endpoint);
    } else {
      endpoint = ollamaEndpoint;
      console.log("Ollama endpoint already has protocol:", endpoint);
    }
    
    // Validate it's a proper URL
    new URL(endpoint);
    
    console.log("Normalized Ollama endpoint for testing:", endpoint);
  } catch (error) {
    console.error("Invalid Ollama URL format:", error);
    return res.status(400).json({
      success: false,
      error: "Invalid URL format for Ollama endpoint",
      details: error.message
    });
  }
  
  try {
    // First check if Ollama is available at the endpoint
    const response = await axios.get(`${endpoint}/api/tags`, {
      timeout: 5000
    });
    
    if (!response.data || !response.data.models) {
      return res.status(400).json({
        error: "Invalid response from Ollama API",
        success: false
      });
    }
    
    const models = response.data.models.map(model => ({
      name: model.name,
      size: model.size,
      modified: model.modified
    }));
    
    return res.json({
      success: true,
      models
    });
  } catch (error) {
    console.error("Error fetching Ollama models:", error);
    return res.status(400).json({
      success: false,
      error: "Failed to connect to Ollama server",
      details: error.message
    });
  }
});

// Test connection to AI service
router.post("/test-connection", authenticateToken, async (req, res) => {
  const { service, endpoint: providedEndpoint } = req.body; // 'openai' or 'ollama' with optional endpoint
  const { id: userId } = req.user;
  const db = req.db;
  
  try {
    // Get user settings
    db.get(
      `SELECT * FROM user_settings WHERE user_id = ?`,
      [userId],
      async (err, settings) => {
        if (err) {
          console.error("Error fetching settings:", err);
          return res.status(500).json({ error: "Database error" });
        }
        
        if (!settings) {
          return res.status(404).json({ error: "Settings not found", success: false });
        }
        
        // Decrypt keys using the same encryption key
        const secretKey = process.env.SETTINGS_ENCRYPTION_KEY || 'secret-key-for-settings-encryption';
        const encryptionKey = getEncryptionKey(secretKey);
        
        const decrypt = (hash, iv) => {
          if (!hash || !iv) return null;
          const decipher = crypto.createDecipheriv(
            algorithm, 
            encryptionKey, 
            Buffer.from(iv, 'hex')
          );
          const decrpyted = Buffer.concat([
            decipher.update(Buffer.from(hash, 'hex')),
            decipher.final()
          ]);
          return decrpyted.toString();
        };
        
        if (service === 'openai') {
          if (!settings.openai_key || !settings.openai_iv) {
            return res.status(400).json({ error: "OpenAI API key not configured", success: false });
          }
          
          let openaiKey;
          try {
            openaiKey = decrypt(settings.openai_key, settings.openai_iv);
          } catch (err) {
            console.error("Error decrypting OpenAI key:", err);
            return res.status(500).json({ error: "Error decrypting API key", success: false });
          }
          
          try {
            // Test OpenAI connection
            const { OpenAI } = require("openai");
            const openai = new OpenAI({ apiKey: openaiKey });
            
            const response = await openai.chat.completions.create({
              model: "gpt-3.5-turbo",
              messages: [{ role: "user", content: "Test connection" }],
              max_tokens: 5
            });
            
            return res.json({ success: true, message: "OpenAI connection successful" });
          } catch (error) {
            console.error("OpenAI connection error:", error);
            return res.status(400).json({ 
              success: false, 
              error: "Failed to connect to OpenAI",
              details: error.message 
            });
          }
        } else if (service === 'ollama') {
          // If an endpoint is provided directly, use it for testing without looking up settings
          if (providedEndpoint) {
            // Validate and normalize the URL
            let endpoint;
            try {
              // Make sure the URL has a protocol
              if (!providedEndpoint.startsWith('http://') && !providedEndpoint.startsWith('https://')) {
                endpoint = `http://${providedEndpoint}`;
              } else {
                endpoint = providedEndpoint;
              }
              
              // Validate it's a proper URL
              new URL(endpoint);
              
              console.log("Testing Ollama connection at:", endpoint);
              
              try {
                // Check if we can connect to the Ollama API
                const modelsResponse = await axios.get(`${endpoint}/api/tags`, {
                  timeout: 5000 
                });
                
                // If we got here, connection is successful
                return res.json({ 
                  success: true, 
                  message: "Ollama connection successful",
                  models: modelsResponse.data.models.map(model => model.name)
                });
              } catch (error) {
                console.error("Ollama connection error:", error);
                return res.status(400).json({ 
                  success: false, 
                  error: "Failed to connect to Ollama",
                  details: error.message 
                });
              }
            } catch (error) {
              console.error("Invalid Ollama URL format:", error);
              return res.status(400).json({
                success: false,
                error: "Invalid URL format for Ollama endpoint",
                details: error.message
              });
            }
          }
          
          // Otherwise look up in settings
          if (!settings.ollama_endpoint || !settings.ollama_iv) {
            return res.status(400).json({ error: "Ollama endpoint not configured", success: false });
          }
          
          let ollamaEndpoint;
          try {
            ollamaEndpoint = decrypt(settings.ollama_endpoint, settings.ollama_iv);
          } catch (err) {
            console.error("Error decrypting Ollama endpoint:", err);
            return res.status(500).json({ error: "Error decrypting Ollama endpoint", success: false });
          }
          
          // Validate and normalize the URL
          let endpoint;
          try {
            // Make sure the URL has a protocol
            if (!ollamaEndpoint.startsWith('http://') && !ollamaEndpoint.startsWith('https://')) {
              endpoint = `http://${ollamaEndpoint}`;
            } else {
              endpoint = ollamaEndpoint;
            }
            
            // Validate it's a proper URL
            new URL(endpoint);
            
            console.log("Attempting to connect to Ollama at:", endpoint);
          } catch (error) {
            console.error("Invalid Ollama URL format:", error);
            return res.status(400).json({
              success: false,
              error: "Invalid URL format for Ollama endpoint",
              details: error.message
            });
          }
          
          try {
            // First check if we can connect to the Ollama API at all
            const modelsResponse = await axios.get(`${endpoint}/api/tags`, {
              timeout: 5000 
            });
            
            // If we got here, connection is successful
            return res.json({ 
              success: true, 
              message: "Ollama connection successful",
              models: modelsResponse.data.models.map(model => model.name)
            });
          } catch (error) {
            console.error("Ollama connection error:", error);
            return res.status(400).json({ 
              success: false, 
              error: "Failed to connect to Ollama",
              details: error.message 
            });
          }
        } else {
          return res.status(400).json({ error: "Invalid service specified", success: false });
        }
      }
    );
  } catch (error) {
    console.error("Test connection error:", error);
    return res.status(500).json({ error: "Server error testing connection", success: false });
  }
});

module.exports = router; 