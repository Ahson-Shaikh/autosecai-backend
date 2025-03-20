// routes/scan.js
const express = require("express");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const os = require("os");
const PDFDocument = require("pdfkit");
const crypto = require('crypto');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "secret";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

// Start a new scan
router.post("/start", authenticateToken, async (req, res) => {
  const { repoName, repoUrl, repoOwner, scanType } = req.body;
  const { id: userId, githubToken } = req.user;
  
  if (!repoName || !repoUrl || !scanType) {
    return res.status(400).json({ error: "Repository information and scan type required" });
  }
  
  try {
    const db = req.db;
    
    // Insert scan record
    db.run(
      `INSERT INTO scans (user_id, repo_name, repo_url, scan_type, status) VALUES (?, ?, ?, ?, ?)`,
      [userId, repoName, repoUrl, scanType, "in_progress"],
      function(err) {
        if (err) {
          console.error("Error creating scan:", err);
          return res.status(500).json({ error: "Error creating scan" });
        }
        
        const scanId = this.lastID;
        
        // Clone repository and begin scanning in background
        const tempDir = path.join(os.tmpdir(), `repo-${scanId}`);
        
        // Return scan ID immediately
        res.json({ 
          scanId, 
          message: "Scan started successfully",
          status: "in_progress" 
        });
        
        // Begin background processing
        beginScan(scanId, repoUrl, tempDir, githubToken, scanType, db, repoName, req.app);
      }
    );
  } catch (error) {
    console.error("Error starting scan:", error);
    return res.status(500).json({ error: "Error starting scan" });
  }
});

// Get scan status
router.get("/:scanId", authenticateToken, (req, res) => {
  const { scanId } = req.params;
  const { id: userId } = req.user;
  const db = req.db;
  
  db.get(
    `SELECT * FROM scans WHERE id = ? AND user_id = ?`,
    [scanId, userId],
    (err, scan) => {
      if (err) {
        console.error("Error fetching scan:", err);
        return res.status(500).json({ error: "Error fetching scan" });
      }
      
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      return res.json({ scan });
    }
  );
});

// Get scan results
router.get("/:scanId/results", authenticateToken, (req, res) => {
  const { scanId } = req.params;
  const { id: userId } = req.user;
  const db = req.db;
  
  db.get(
    `SELECT * FROM scans WHERE id = ? AND user_id = ?`,
    [scanId, userId],
    (err, scan) => {
      if (err) {
        console.error("Error fetching scan:", err);
        return res.status(500).json({ error: "Error fetching scan" });
      }
      
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      
      db.all(
        `SELECT * FROM vulnerabilities WHERE scan_id = ?`,
        [scanId],
        (err, vulnerabilities) => {
          if (err) {
            console.error("Error fetching vulnerabilities:", err);
            return res.status(500).json({ error: "Error fetching vulnerabilities" });
          }
          
          return res.json({ scan, vulnerabilities });
        }
      );
    }
  );
});

// Get PDF report
router.get("/:scanId/report", (req, res) => {
  const { scanId } = req.params;
  
  // Check for token either in Authorization header or query parameter
  let token;
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Get token from Authorization header
    token = authHeader.split(' ')[1];
  } else if (req.query.token) {
    // Get token from query parameter
    token = req.query.token;
  } else {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  // Verify the token
  let userId;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    userId = decoded.id;
    if (!userId) {
      throw new Error("Invalid token format");
    }
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(403).json({ error: "Invalid or expired token" });
  }
  
  const db = req.db;
  db.get(
    `SELECT r.report_path, s.repo_name 
     FROM reports r 
     JOIN scans s ON r.scan_id = s.id 
     WHERE r.scan_id = ? AND s.user_id = ?`,
    [scanId, userId],
    (err, report) => {
      if (err) {
        console.error("Error fetching report:", err);
        return res.status(500).json({ error: "Error fetching report" });
      }
      
      if (!report || !report.report_path) {
        return res.status(404).json({ error: "Report not found" });
      }
      
      // Check if file exists
      if (!fs.existsSync(report.report_path)) {
        console.error("Report file not found:", report.report_path);
        return res.status(404).json({ error: "Report file not found" });
      }
      
      // Set headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=report-${report.repo_name}.pdf`);
      
      // Stream the file
      const fileStream = fs.createReadStream(report.report_path);
      fileStream.pipe(res);
      
      // Handle errors
      fileStream.on('error', (err) => {
        console.error("Error streaming file:", err);
        if (!res.headersSent) {
          return res.status(500).json({ error: "Error streaming file" });
        }
      });
    }
  );
});

// Get all scans for user
router.get("/", authenticateToken, (req, res) => {
  const { id: userId } = req.user;
  const db = req.db;
  
  db.all(
    `SELECT * FROM scans WHERE user_id = ? ORDER BY started_at DESC`,
    [userId],
    (err, scans) => {
      if (err) {
        console.error("Error fetching scans:", err);
        return res.status(500).json({ error: "Error fetching scans" });
      }
      
      return res.json({ scans });
    }
  );
});

// Cancel an ongoing scan
router.post("/:scanId/cancel", authenticateToken, (req, res) => {
  const scanId = req.params.scanId;
  const { id: userId } = req.user;
  const db = req.db;
  
  // First check if scan exists and belongs to user
  db.get(
    `SELECT * FROM scans WHERE id = ? AND user_id = ?`,
    [scanId, userId],
    (err, scan) => {
      if (err) {
        console.error("Error fetching scan:", err);
        return res.status(500).json({ error: "Database error" });
      }
      
      if (!scan) {
        return res.status(404).json({ error: "Scan not found or not owned by user" });
      }
      
      if (scan.status !== "in_progress") {
        return res.status(400).json({ error: "Scan is not in progress" });
      }
      
      // Update scan status to cancelled
      db.run(
        `UPDATE scans SET status = 'cancelled', completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
        [scanId],
        (updateErr) => {
          if (updateErr) {
            console.error("Error updating scan status:", updateErr);
            return res.status(500).json({ error: "Error updating scan status" });
          }
          
          console.log(`Scan ${scanId} cancelled by user ${userId}`);
          
          // Note: In a real implementation, you would want to kill any running background processes
          // This is a simplified implementation that just updates the status
          
          return res.json({ 
            success: true,
            message: "Scan cancelled" 
          });
        }
      );
    }
  );
});

// Check if Ollama is available
async function isOllamaAvailable(endpoint, model) {
  // If no endpoint is provided, we can't check availability
  if (!endpoint) {
    console.log("No Ollama endpoint provided, can't check availability");
    return false;
  }
  
  try {
    console.log(`Checking Ollama availability at: ${endpoint}`);
    
    // Simple ping to check if Ollama is running
    const response = await axios.get(`${endpoint}/api/version`, {
      timeout: 10000  // 10 second timeout for availability check
    });
    console.log(`Ollama version check response from ${endpoint}:`, response.status);
    
    // Skip model check for remote Ollama instances that might not support /api/tags
    if (model && !endpoint.includes('easypanel.host')) {
      try {
        console.log(`Checking if model ${model} exists at ${endpoint}`);
        const modelResponse = await axios.get(`${endpoint}/api/tags`, {
          timeout: 10000
        });
        const modelExists = modelResponse.data.models?.some(m => m.name === model);
        if (!modelExists) {
          console.log(`Ollama is available at ${endpoint} but model ${model} not found`);
          return false;
        }
      } catch (modelErr) {
        console.log(`Error checking Ollama models at ${endpoint}:`, modelErr.message);
        // Continue anyway - older Ollama versions might not have /api/tags endpoint
        // or the endpoint might be a remote service that doesn't support model listing
      }
    }
    
    return response.status === 200;
  } catch (error) {
    console.error(`Error checking Ollama availability at ${endpoint}:`, error.message);
    return false;
  }
}

// Begin scan with the specified settings
async function beginScan(scanId, repoUrl, tempDir, githubToken, scanType, db, repoName, app) {
  console.log(`=== [Scan ${scanId}] STARTING SCAN with debug tracing ===`);
  
  // Get Socket.IO instance from app
  const io = app.get('io');
  
  // Store AI configuration at the top level of the function so it's available throughout
  let openaiApiKey = null;
  let ollamaEndpoint = null;
  let ollamaModel = null; // No default model
  let aiService = "Default AI";
  let aiModel = "default";
  
  // Helper function to emit scan logs - MOVED TO TOP
  const emitScanLog = (message, phase = null) => {
    console.log(`Scan ${scanId}: ${message}`);
    
    // Debug trace - check if Ollama endpoint is still valid in this scope
    console.log(`[TRACE] emitScanLog scope - ollamaEndpoint = ${ollamaEndpoint}, ollamaModel = ${ollamaModel}`);
    
    if (io) {
      const data = {
        timestamp: new Date().toISOString(),
        message: message
      };
      
      if (phase) {
        data.phase = phase;
        // Only try to update scan_phase if needed, with error handling
        try {
          db.run(`UPDATE scans SET scan_phase = ? WHERE id = ?`, [phase, scanId], (err) => {
            if (err) {
              // Just log the error but don't stop execution
              console.error(`Warning: Could not update scan phase: ${err.message}`);
            }
          });
        } catch (error) {
          console.error(`Error in scan phase update: ${error.message}`);
        }
      }
      
      io.to(`scan-${scanId}`).emit('scan-log', data);
    }
  };
  
  // Helper function to update and emit current file info
  const emitFileProgress = (filePath, fileType) => {
    if (io) {
      io.to(`scan-${scanId}`).emit('file-progress', {
        timestamp: new Date().toISOString(),
        filePath,
        fileType
      });
    }
  };
  
  try {
    // Get the user settings from the scanId
    const scan = await new Promise((resolve, reject) => {
      db.get(`SELECT user_id FROM scans WHERE id = ?`, [scanId], (err, row) => {
        if (err) {
          console.error(`Error getting user_id for scan ${scanId}:`, err);
          reject(err);
        } else {
          console.log(`Retrieved scan record for scan ${scanId}:`, row);
          resolve(row);
        }
      });
    });
    
    if (!scan) {
      emitScanLog("Scan not found", "failed");
      throw new Error("Scan not found");
    }
    
    console.log(`Using user_id ${scan.user_id} to fetch settings`);
    
    // Get user's AI settings
    emitScanLog("Fetching AI configuration...", "initializing");
    const userSettings = await new Promise((resolve, reject) => {
      console.log(`Executing SQL query to get settings for user ${scan.user_id}`);
      db.get(`SELECT * FROM user_settings WHERE user_id = ?`, [scan.user_id], (err, settings) => {
        if (err) {
          console.error(`Error getting settings for user ${scan.user_id}:`, err);
          reject(err);
        } else {
          if (settings) {
            console.log(`Found settings for user ${scan.user_id}:`, {
              has_openai: !!settings.openai_key,
              has_openai_iv: !!settings.openai_iv,
              has_ollama: !!settings.ollama_endpoint,
              has_ollama_iv: !!settings.ollama_iv,
              ollama_model: settings.ollama_model || '(not set)'
            });
          } else {
            console.error(`No settings found for user ${scan.user_id}`);
          }
          resolve(settings);
        }
      });
    });
    
    if (!userSettings) {
      emitScanLog("No AI configuration found for this user", "warning");
      emitScanLog("Please configure AI settings before scanning", "failed");
      throw new Error("No user settings found");
    }
    
    console.log("USER SETTINGS RETRIEVED:", {
      hasOpenAI: !!(userSettings?.openai_key && userSettings?.openai_iv),
      hasOllama: !!(userSettings?.ollama_endpoint && userSettings?.ollama_iv),
      ollamaModel: userSettings?.ollama_model || 'Not set'
    });
    
    // Check if Ollama settings is set and has model specified
    if (!(userSettings.ollama_endpoint && userSettings.ollama_iv)) {
      emitScanLog("No Ollama endpoint configured", "failed");
      throw new Error("Ollama endpoint is not provided in settings");
    }
    
    if (!userSettings.ollama_model) {
      emitScanLog("No Ollama model specified in settings", "failed");
      throw new Error("Ollama model is not specified in settings");
    }
    
    // Decrypt credentials if they exist
    const secretKey = process.env.SETTINGS_ENCRYPTION_KEY || 'secret-key-for-settings-encryption';
    const algorithm = 'aes-256-ctr';
    
    // Create encryption key from secret
    const getEncryptionKey = (secret) => {
      // Use a crypto hash function to create a consistent 32-byte key - MATCH SETTINGS MODULE
      const key = crypto.createHash('sha256').update(String(secret)).digest();
      console.log("Settings encryption - Key first 5 chars:", key.toString('hex').substring(0, 10) + "...");
      return key;
    };
    
    const encryptionKey = getEncryptionKey(secretKey);
    
    // Helper function to decrypt values
    const decrypt = (hash, iv) => {
      if (!hash || !iv) {
        console.log("Cannot decrypt: missing hash or iv");
        return null;
      }
      
      try {
        console.log(`Attempting to decrypt: hash=${hash.substring(0, 10)}..., iv=${iv.substring(0, 10)}...`);
        const decipher = crypto.createDecipheriv(
          algorithm, 
          encryptionKey, 
          Buffer.from(iv, 'hex')
        );
        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(hash, 'hex')),
          decipher.final()
        ]);
        const result = decrypted.toString();
        console.log("Decryption successful");
        return result;
      } catch (error) {
        console.error("Decryption error:", error.message);
        throw new Error(`Failed to decrypt Ollama endpoint: ${error.message}`);
      }
    };
    
    // Decrypt OpenAI API key if exists
    openaiApiKey = process.env.OPENAI_API_KEY || null;
    
    if (userSettings && userSettings.openai_key && userSettings.openai_iv) {
      try {
        openaiApiKey = decrypt(userSettings.openai_key, userSettings.openai_iv);
        
        // Validate the OpenAI key - check if it's a real key and not a placeholder
        if (!openaiApiKey || openaiApiKey.includes('your_') || openaiApiKey.length < 20) {
          emitScanLog("Invalid OpenAI API key detected, will use Ollama instead", "initializing");
          openaiApiKey = null; // Force using Ollama instead
        } else {
          aiService = "OpenAI";
          aiModel = "gpt-3.5-turbo";
          emitScanLog(`Using OpenAI for vulnerability scanning`, "initializing");
        }
      } catch (error) {
        console.error("Error decrypting OpenAI API key:", error);
        emitScanLog("Error decrypting OpenAI API key, using fallback AI", "initializing");
        openaiApiKey = null; // Force using Ollama instead
      }
    } else {
      emitScanLog("No OpenAI API key configured, will use Ollama", "initializing");
    }
    
    // Decrypt Ollama endpoint if exists
    if (userSettings && userSettings.ollama_endpoint && userSettings.ollama_iv) {
      try {
        ollamaEndpoint = decrypt(userSettings.ollama_endpoint, userSettings.ollama_iv);
        console.log("Decrypted Ollama endpoint:", ollamaEndpoint);
        
        // Get model from settings and validate
        ollamaModel = userSettings.ollama_model;
        console.log("Using Ollama model from settings:", ollamaModel);
        
        if (!ollamaModel) {
          emitScanLog("No Ollama model specified in settings", "failed");
          throw new Error("Ollama model is not specified in settings");
        }
        
        aiService = "Ollama";
        aiModel = ollamaModel;
        emitScanLog(`Using Ollama with model ${ollamaModel} for vulnerability scanning`, "initializing");
        
        // Critical checkpoint for debugging
        console.log("CRITICAL CHECKPOINT - AFTER SETTINGS LOADED:");
        console.log("ollamaEndpoint =", ollamaEndpoint);
        console.log("ollamaModel =", ollamaModel);
      } catch (error) {
        console.error("Error decrypting Ollama endpoint:", error);
        emitScanLog(`Error decrypting Ollama endpoint: ${error.message}`, "failed");
        throw new Error(`Failed to decrypt Ollama endpoint: ${error.message}`);
      }
    } else {
      // No Ollama endpoint configured
      emitScanLog("No Ollama endpoint configured", "failed");
      throw new Error("Ollama endpoint is not provided in settings");
    }
  } catch (error) {
    console.error("Error in beginScan:", error);
    emitScanLog(`Error in beginScan: ${error.message}`, "failed");
    throw error;
  }
  
  // Verify Ollama availability
  const ollamaAvailable = await isOllamaAvailable(ollamaEndpoint, ollamaModel);
  console.log("Ollama availability check result:", ollamaAvailable);
  if (!ollamaAvailable) {
    emitScanLog(`Warning: Ollama is not available at ${ollamaEndpoint} or model ${ollamaModel} is not found`, "warning");
    emitScanLog("Scan will continue but may fail if Ollama cannot be reached", "warning");
  }
  
  // Clone the repository
  emitScanLog(`Initializing security scan for ${repoName}...`, "initializing");
  emitScanLog("Creating temporary workspace...");
  
  await new Promise((resolve, reject) => {
    fs.mkdir(tempDir, { recursive: true }, (err) => {
      if (err) reject(err);
      
      emitScanLog(`Cloning repository ${repoName} from GitHub...`, "cloning");
      
      // Check if repoUrl is valid and properly formatted
      if (!repoUrl || typeof repoUrl !== 'string') {
        const error = new Error(`Invalid repository URL: ${repoUrl}`);
        emitScanLog(`Error cloning repository: Invalid URL format`, "failed");
        return reject(error);
      }
      
      // Extract the repository path from the URL
      let repoPath;
      try {
        repoPath = repoUrl.split('github.com/')[1];
        if (!repoPath) throw new Error('Could not parse GitHub repository path');
      } catch (error) {
        emitScanLog(`Error parsing repository URL: ${repoUrl}`, "failed");
        return reject(error);
      }

      const gitCommand = `git clone https://${githubToken}@github.com/${repoPath} ${tempDir}`;
      exec(gitCommand, (error) => {
        if (error) {
          emitScanLog(`Error cloning repository: ${error.message}`, "failed");
          reject(error);
        } else {
          emitScanLog("Repository cloned successfully");
          resolve();
        }
      });
    });
  });
  
  // Get list of files to scan
  emitScanLog("Analyzing project structure...", "analyzing");
  emitScanLog("Identifying language patterns and file types...");
  const files = await getFilesToScan(tempDir, scanType);
  emitScanLog(`Found ${files.length} files to scan`);
  
  // Analyze each file
  const vulnerabilities = [];
  
  emitScanLog("Beginning security scan...", "scanning");
  emitScanLog(`Using ${aiService} (${aiModel}) for analysis`);
  
  // CRITICAL CHECK POINT: Log the endpoint value right before the loop
  console.log("==== CRITICAL CHECK POINT BEFORE FILE LOOP ====");
  console.log("ollamaEndpoint =", ollamaEndpoint);
  console.log("aiService =", aiService);
  console.log("aiModel =", aiModel);
  console.log("============================================");
  
  for (const file of files) {
    try {
      // Log variables again to verify they're still available
      console.log(`Processing file ${file}, ollamaEndpoint =`, ollamaEndpoint);
      
      const filePath = path.join(tempDir, file);
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const fileExtension = path.extname(file).substring(1);
      
      // Emit current file info
      emitFileProgress(file, fileExtension);
      emitScanLog(`Scanning ${fileExtension.toUpperCase()} file: ${file}`);
      
      // Log Ollama endpoint before using it
      console.log(`Before analyzing ${file}, ollamaEndpoint =`, ollamaEndpoint);
      
      // Use AI to analyze the code
      let analysisResult;
      
      if (ollamaEndpoint && !(ollamaEndpoint.includes('your_') || ollamaEndpoint.length < 20)) {
        emitScanLog(`Analyzing with Ollama: ${file}`);
        console.log(`Analyzing ${file} with Ollama, endpoint =`, ollamaEndpoint);
        analysisResult = await analyzeWithOllama(fileContent, file, scanType, ollamaEndpoint, ollamaModel);
      } else {
        emitScanLog(`Analyzing with Ollama (${ollamaModel}): ${file}`);
        console.log(`Before analyzing ${file}, ollamaEndpoint = ${ollamaEndpoint}, ollamaModel = ${ollamaModel}`);
        analysisResult = await analyzeWithOllama(fileContent, file, scanType, ollamaEndpoint, ollamaModel);
      }
      
      // Report findings for this file
      if (analysisResult.length > 0) {
        emitScanLog(`Found ${analysisResult.length} potential vulnerabilities in ${file}`);
        
        // Log each vulnerability
        analysisResult.forEach(vuln => {
          emitScanLog(`[${vuln.severity}] ${vuln.title} - Line ${vuln.lineNumber}`);
        });
      } else {
        emitScanLog(`No vulnerabilities found in ${file}`);
      }
      
      // Add vulnerabilities to the list
      vulnerabilities.push(...analysisResult.map(v => ({
        scan_id: scanId,
        severity: v.severity,
        title: v.title,
        description: v.description,
        file_path: file,
        line_number: v.lineNumber,
        remediation: v.remediation
      })));
    } catch (fileError) {
      console.error(`Error analyzing file ${file}:`, fileError);
      emitScanLog(`Error analyzing file ${file}: ${fileError.message}`);
    }
  }
  
  // Save vulnerabilities to database
  emitScanLog("Analysis complete. Processing results...", "reporting");
  emitScanLog(`Found ${vulnerabilities.length} total vulnerabilities`);
  
  const severityCounts = {
    High: vulnerabilities.filter(v => v.severity === 'High').length,
    Medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
    Low: vulnerabilities.filter(v => v.severity === 'Low').length
  };
  
  emitScanLog(`Severity breakdown: ${severityCounts.High} High, ${severityCounts.Medium} Medium, ${severityCounts.Low} Low`);
  emitScanLog("Saving results to database...");
  
  for (const vuln of vulnerabilities) {
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO vulnerabilities (scan_id, severity, title, description, file_path, line_number, remediation) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [vuln.scan_id, vuln.severity, vuln.title, vuln.description, vuln.file_path, vuln.line_number, vuln.remediation],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }
  
  // Generate PDF report
  emitScanLog("Generating PDF report...");
  const reportPath = await generatePDFReport(scanId, repoName, vulnerabilities, db);
  
  // Save report path
  emitScanLog("Finalizing report...");
  await new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO reports (scan_id, report_path) VALUES (?, ?)`,
      [scanId, reportPath],
      (err) => {
        if (err) reject(err);
        else resolve();
      }
    );
  });
  
  // Update scan status to completed
  emitScanLog("Scan completed successfully!", "completed");
  await new Promise((resolve, reject) => {
    db.run(
      `UPDATE scans SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [scanId],
      (err) => {
        if (err) reject(err);
        else resolve();
      }
    );
  });
  
  // Clean up temp directory
  emitScanLog("Cleaning up temporary files...");
  fs.rm(tempDir, { recursive: true, force: true }, (err) => {
    if (err) console.error(`Error removing temp directory: ${err.message}`);
  });
}

// Get files to scan based on scan type
async function getFilesToScan(repoDir, scanType) {
  return new Promise((resolve, reject) => {
    const command = scanType === "SAST" 
      ? `find ${repoDir} -type f -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" -o -name "*.py" -o -name "*.php" -o -name "*.java" -o -name "*.go" | sed "s|${repoDir}/||"`
      : `find ${repoDir} -type f -name "*.html" -o -name "*.htm" -o -name "*.php" | sed "s|${repoDir}/||"`;
    
    exec(command, (error, stdout) => {
      if (error) {
        reject(error);
      } else {
        const files = stdout.split('\n').filter(Boolean);
        resolve(files);
      }
    });
  });
}

// Analyze code with OpenAI
async function analyzeWithOpenAI(code, filePath, scanType, apiKey = OPENAI_API_KEY) {
  try {
    // Validate API key first
    if (!apiKey || apiKey.includes('your_') || apiKey.length < 20) {
      console.log("Invalid OpenAI API key detected, skipping OpenAI analysis");
      return [];
    }
    
    // Try to import OpenAI module, if it fails, provide helpful error
    let OpenAI;
    try {
      OpenAI = require("openai").OpenAI;
    } catch (importError) {
      console.error("Error importing OpenAI module:", importError.message);
      console.error("To use OpenAI, please install the package with: npm install openai");
      return [];
    }
    
    const openai = new OpenAI({ apiKey });
    
    const fileExtension = path.extname(filePath).substring(1);
    
    const prompt = scanType === "SAST"
      ? `You are a security expert analyzing code for vulnerabilities. Examine this ${fileExtension} code and identify security issues like injection vulnerabilities, authentication problems, sensitive data exposure, etc. For each vulnerability found, provide: 1) Severity (High/Medium/Low), 2) Title, 3) Description, 4) Line number (as "lineNumber"), 5) Remediation advice (as "remediation"). Format as a JSON array.`
      : `You are a security expert analyzing web application code for vulnerabilities. Examine this ${fileExtension} code and identify security issues like XSS, CSRF, insecure cookies, client-side validation issues, etc. For each vulnerability found, provide: 1) Severity (High/Medium/Low), 2) Title, 3) Description, 4) Line number (as "lineNumber"), 5) Remediation advice (as "remediation"). Format as a JSON array.`;
    
    console.log(`Using OpenAI to analyze ${filePath}`);
    
    const response = await openai.chat.completions.create({
      model: "gpt-3.5-turbo-0125",
      messages: [
        { role: "system", content: prompt },
        { role: "user", content: code }
      ],
      response_format: { type: "json_object" }
    });
    
    try {
      const result = JSON.parse(response.choices[0].message.content);
      return Array.isArray(result) ? result : [];
    } catch (parseError) {
      console.error("Error parsing OpenAI response:", parseError);
      return [];
    }
  } catch (error) {
    console.error("Error calling OpenAI API:", error);
    return [];
  }
}

// Analyze code with Ollama
async function analyzeWithOllama(code, filePath, scanType, ollamaEndpoint, ollamaModel) {
  // Validate that both endpoint and model are provided
  console.log(`Analyzing ${filePath} with Ollama, endpoint = ${ollamaEndpoint}, model = ${ollamaModel}`);
  
  if (!ollamaEndpoint) {
    console.error("No Ollama endpoint provided for analysis");
    return [];
  }
  
  if (!ollamaModel) {
    console.error("No Ollama model specified for analysis");
    return [];
  }
  
  const prompt = `I have a file located at ${filePath} that I'd like you to analyze for security vulnerabilities.
  Focus on identifying ONLY CRITICAL security vulnerabilities, not code quality or general bugs.
  
  Scan type: ${scanType}
  
  Here is the code to analyze:
  
  \`\`\`
  ${code}
  \`\`\`
  
  Please respond with a JSON array of vulnerabilities. Each vulnerability should be an object with the following properties:
  - title: A short title for the vulnerability
  - description: A detailed description of the vulnerability
  - severity: The severity level (critical, high, medium, low)
  - line_number: The line number where the vulnerability occurs
  - code: The vulnerable code snippet
  - recommendation: Your recommendation to fix the issue
  
  ONLY respond with the JSON array, nothing else. The array may be empty if no vulnerabilities are found.
  `;
  
  try {
    console.log(`Making Ollama API request to ${ollamaEndpoint}/api/generate for model ${ollamaModel}`);
    
    // Ensure URL doesn't have trailing slash before appending the path
    const baseUrl = ollamaEndpoint.endsWith('/') ? ollamaEndpoint.slice(0, -1) : ollamaEndpoint;
    const url = `${baseUrl}/api/generate`;
    console.log(`Final Ollama API URL: ${url}`);
    
    // Set longer timeout for remote instances (2 minutes)
    const timeout = ollamaEndpoint.includes('localhost') ? 60000 : 120000;
    
    const response = await axios.post(url, {
      model: ollamaModel,
      prompt: prompt,
      stream: false
    }, {
      timeout: timeout,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    if (response.data && response.data.response) {
      const result = response.data.response.trim();
      try {
        // Extract JSON if it's surrounded by markdown code blocks
        let jsonStr = result;
        if (result.includes('```json')) {
          jsonStr = result.split('```json')[1].split('```')[0].trim();
        } else if (result.includes('```')) {
          jsonStr = result.split('```')[1].split('```')[0].trim();
        }
        
        // Further clean the JSON string
        jsonStr = jsonStr.replace(/^```(json)?/, '').replace(/```$/, '').trim();
        
        const vulnerabilities = JSON.parse(jsonStr);
        console.log(`Found ${vulnerabilities.length} vulnerabilities in ${filePath}`);
        return vulnerabilities;
      } catch (error) {
        console.error(`Error parsing Ollama response for ${filePath}:`, error.message);
        console.log("Raw Ollama response:", result);
        return [];
      }
    }
    
    return [];
  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      console.error(`Connection refused to Ollama at ${ollamaEndpoint}`);
      return [];
    } else if (error.code === 'ETIMEDOUT' || error.code === 'ESOCKETTIMEDOUT') {
      console.error(`Connection timed out to Ollama at ${ollamaEndpoint}`);
      return [];
    } else {
      console.error(`Error analyzing with Ollama for ${filePath}:`, error.message);
      return [];
    }
  }
}

// Generate PDF report
async function generatePDFReport(scanId, repoName, vulnerabilities, db) {
  return new Promise((resolve, reject) => {
    try {
      const reportsDir = path.join(__dirname, '../reports');
      fs.mkdirSync(reportsDir, { recursive: true });
      
      const reportPath = path.join(reportsDir, `report-${scanId}.pdf`);
      const doc = new PDFDocument();
      const stream = fs.createWriteStream(reportPath);
      
      doc.pipe(stream);
      
      // Title and header
      doc.fontSize(25).text('Security Scan Report', { align: 'center' });
      doc.moveDown();
      doc.fontSize(15).text(`Repository: ${repoName}`, { align: 'center' });
      doc.moveDown();
      doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
      doc.moveDown().moveDown();
      
      // Summary
      const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
      const mediumCount = vulnerabilities.filter(v => v.severity === 'Medium').length;
      const lowCount = vulnerabilities.filter(v => v.severity === 'Low').length;
      
      doc.fontSize(16).text('Summary', { underline: true });
      doc.moveDown();
      doc.fontSize(12).text(`Total Vulnerabilities: ${vulnerabilities.length}`);
      doc.text(`High Severity: ${highCount}`);
      doc.text(`Medium Severity: ${mediumCount}`);
      doc.text(`Low Severity: ${lowCount}`);
      doc.moveDown().moveDown();
      
      // Vulnerability details
      doc.fontSize(16).text('Vulnerabilities', { underline: true });
      doc.moveDown();
      
      vulnerabilities.forEach((vuln, index) => {
        const severityColor = vuln.severity === 'High' ? '#FF0000' : vuln.severity === 'Medium' ? '#FFA500' : '#FFFF00';
        
        doc.fontSize(14).fillColor(severityColor).text(`${index + 1}. ${vuln.title} (${vuln.severity})`);
        doc.fillColor('black');
        doc.fontSize(12).text(`File: ${vuln.file_path}`);
        doc.text(`Line: ${vuln.line_number}`);
        doc.moveDown();
        doc.text('Description:');
        doc.text(vuln.description);
        doc.moveDown();
        doc.text('Remediation:');
        doc.text(vuln.remediation);
        doc.moveDown().moveDown();
      });
      
      // Footer
      doc.fontSize(10).text('Generated by AutoSecAI', { align: 'center' });
      
      doc.end();
      
      stream.on('finish', () => {
        resolve(reportPath);
      });
      
      stream.on('error', (err) => {
        reject(err);
      });
    } catch (error) {
      reject(error);
    }
  });
}

module.exports = router;