// mega-upload-backend/index.js
const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const fs = require('fs');
const fsPromises = fs.promises;
const path = require('path');
require('dotenv').config();

const app = express();

// Configure CORS – allow only your frontend
app.use(cors({
  origin: 'https://baldi-mods-hub.vercel.app', // your frontend URL
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

// Set up multer to use /tmp directory (works on Railway)
const upload = multer({ dest: '/tmp/' });

const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;

if (!MEGA_EMAIL || !MEGA_PASSWORD) {
  console.error('❌ Missing Mega credentials in .env');
  process.exit(1);
}

// Helper to add random delay (1-4 seconds) – optional, can be removed if not needed
const randomDelay = () => new Promise(resolve => setTimeout(resolve, Math.floor(Math.random() * 3000) + 1000));

// Helper to upload a single file with retry logic
async function uploadFile(file, prefix, uploadFolder) {
  if (!file) throw new Error('No file provided');
  
  const filePath = file.path;
  // Check if file exists
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
    readStream.destroy(); // clean up stream
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

app.post('/upload', upload.fields([
  { name: 'mainScreenshot', maxCount: 1 },
  { name: 'screenshots', maxCount: 4 },
  { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
  const allFiles = [];
  try {
    console.log('Upload started at', new Date().toISOString());

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

    // Upload additional screenshots (max 2 per your frontend)
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
    // Clean up temp files even on error
    cleanupFiles(allFiles);
    res.status(500).json({ error: error.message });
  }
});

// Health check endpoint (optional)
app.get('/health', (req, res) => {
  res.send('OK');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Mega upload backend running on port ${PORT}`);
});