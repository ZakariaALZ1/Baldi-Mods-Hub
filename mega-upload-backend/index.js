// mega-upload-backend/index.js
const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const fs = require('fs');
const fsPromises = fs.promises;
const os = require('os');
const path = require('path');
require('dotenv').config();

const app = express();

// Configure CORS – allow only your frontend
app.use(cors({
  origin: 'https://baldi-mods-hub.vercel.app',
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

// Use system temp directory (works reliably on Railway)
const upload = multer({ 
  dest: os.tmpdir(),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;

if (!MEGA_EMAIL || !MEGA_PASSWORD) {
  console.error('❌ Missing Mega credentials in .env');
  process.exit(1);
}

// Helper to add random delay (optional)
const randomDelay = () => new Promise(resolve => setTimeout(resolve, Math.floor(Math.random() * 3000) + 1000));

// Helper to upload a single file to Mega
async function uploadFile(file, prefix, uploadFolder) {
  if (!file) throw new Error('No file provided');
  
  const filePath = file.path;
  try {
    await fsPromises.access(filePath, fs.constants.R_OK);
  } catch (err) {
    throw new Error(`File not accessible: ${filePath}`);
  }

  const stats = await fsPromises.stat(filePath);
  const fileName = `${prefix}_${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
  
  const readStream = fs.createReadStream(filePath);
  
  try {
    const uploaded = await uploadFolder.upload({
      name: fileName,
      size: stats.size
    }, readStream).complete;
    return uploaded;
  } catch (err) {
    throw new Error(`Mega upload failed for ${fileName}: ${err.message}`);
  } finally {
    readStream.destroy();
  }
}

// Clean up temporary files
function cleanupFiles(files) {
  files.forEach(file => {
    if (file && file.path) {
      fs.unlink(file.path, (err) => {
        if (err) console.warn(`Failed to delete temp file ${file.path}:`, err.message);
      });
    }
  });
}

// Check if temp directory is writable
try {
  fs.accessSync(os.tmpdir(), fs.constants.W_OK);
  console.log(`✅ Temp directory is writable: ${os.tmpdir()}`);
} catch (e) {
  console.error(`❌ Temp directory not writable: ${os.tmpdir()}`, e);
  process.exit(1);
}

// Main upload endpoint with multer error handling
app.post('/upload', (req, res) => {
  const uploadMiddleware = upload.fields([
    { name: 'mainScreenshot', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 },
    { name: 'modFile', maxCount: 1 }
  ]);

  uploadMiddleware(req, res, async (err) => {
    // Handle multer errors (e.g., file too large, wrong field name)
    if (err) {
      console.error('Multer error:', err);
      return res.status(400).json({ error: err.message });
    }

    // Log received files for debugging
    console.log('req.files:', JSON.stringify(req.files, (key, value) => {
      if (key === 'path') return '[path]'; // hide full path
      return value;
    }, 2));
    console.log('req.body:', req.body);

    const allFiles = [];
    try {
      // Collect all files for cleanup later
      if (req.files) {
        if (req.files.mainScreenshot) allFiles.push(...req.files.mainScreenshot);
        if (req.files.screenshots) allFiles.push(...req.files.screenshots);
        if (req.files.modFile) allFiles.push(...req.files.modFile);
      }

      // Validate required files
      if (!req.files?.mainScreenshot || !req.files?.modFile) {
        throw new Error('Missing required files (mainScreenshot or modFile)');
      }

      // Optional delay
      await randomDelay();

      // Connect to Mega
      console.log('Connecting to Mega...');
      const storage = await new Storage({ email: MEGA_EMAIL, password: MEGA_PASSWORD }).ready;
      const folderName = `baldi_mod_${Date.now()}`;
      const uploadFolder = await storage.mkdir(folderName);
      console.log(`Created Mega folder: ${folderName}`);

      // Upload main screenshot
      console.log('Uploading main screenshot...');
      const mainFile = req.files.mainScreenshot[0];
      const mainUpload = await uploadFile(mainFile, 'main', uploadFolder);

      // Upload additional screenshots (max 4)
      const extraFiles = req.files.screenshots || [];
      console.log(`Uploading ${extraFiles.length} additional screenshots...`);
      const extraUploads = await Promise.all(extraFiles.map(f => uploadFile(f, 'extra', uploadFolder)));

      // Upload mod file
      console.log('Uploading mod file...');
      const modFile = req.files.modFile[0];
      const modUpload = await uploadFile(modFile, 'mod', uploadFolder);

      // Generate shareable links
      console.log('Generating links...');
      const mainLink = await mainUpload.link();
      const extraLinks = await Promise.all(extraUploads.map(f => f.link()));
      const modLink = await modUpload.link();

      // Close Mega session
      await storage.close();
      console.log('Mega session closed.');

      // Clean up temp files
      cleanupFiles(allFiles);

      // Send response
      res.json({
        mainScreenshotUrl: mainLink,
        screenshotUrls: extraLinks,
        modFileUrl: modLink
      });

    } catch (error) {
      console.error('Upload error:', error);
      cleanupFiles(allFiles);
      res.status(500).json({ error: error.message });
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.send('OK');
});

// Optional test endpoint to verify file reception (remove in production)
app.post('/test-upload', upload.fields([
  { name: 'mainScreenshot', maxCount: 1 },
  { name: 'screenshots', maxCount: 4 },
  { name: 'modFile', maxCount: 1 }
]), (req, res) => {
  console.log('Test upload received');
  const fileInfo = {};
  for (const field in req.files) {
    fileInfo[field] = req.files[field].map(f => ({
      originalname: f.originalname,
      size: f.size,
      mimetype: f.mimetype
    }));
  }
  res.json({ files: fileInfo });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Mega upload backend running on port ${PORT}`);
});