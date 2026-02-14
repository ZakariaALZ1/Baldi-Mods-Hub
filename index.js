// mega-upload-backend/index.js
const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors()); // Allow requests from your Vercel domain

// Configure multer to store files temporarily (diskStorage handles large files better)
const upload = multer({ dest: '/tmp/' }); // Use /tmp on Railway/Render

// Mega.nz credentials from environment variables
const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;

if (!MEGA_EMAIL || !MEGA_PASSWORD) {
  console.error('❌ Missing Mega credentials in .env');
  process.exit(1);
}

app.post('/upload', upload.fields([
  { name: 'mainScreenshot', maxCount: 1 },
  { name: 'screenshots', maxCount: 4 },
  { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('Upload started...');
    const storage = await new Storage({ email: MEGA_EMAIL, password: MEGA_PASSWORD }).ready;

    // Create a unique folder for this upload
    const folderName = `baldi_mod_${Date.now()}`;
    const uploadFolder = await storage.mkdir(folderName);

    // Helper to upload a file from disk
    const uploadFile = async (file, prefix) => {
      const filePath = file.path;
      const fileName = `${prefix}_${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
      const stats = await require('fs').promises.stat(filePath);
      const readStream = require('fs').createReadStream(filePath);
      const uploaded = await uploadFolder.upload({
        name: fileName,
        size: stats.size
      }, readStream).complete;
      return uploaded;
    };

    // Upload main screenshot
    const mainFile = req.files['mainScreenshot'][0];
    const mainUpload = await uploadFile(mainFile, 'main');

    // Upload additional screenshots
    const extraFiles = req.files['screenshots'] || [];
    const extraUploads = await Promise.all(extraFiles.map(f => uploadFile(f, 'extra')));

    // Upload mod file
    const modFile = req.files['modFile'][0];
    const modUpload = await uploadFile(modFile, 'mod');

    // Generate public links
    const mainLink = await mainUpload.link();
    const extraLinks = await Promise.all(extraUploads.map(f => f.link()));
    const modLink = await modUpload.link();

    // Clean up temporary files
    const fs = require('fs');
    [mainFile, ...extraFiles, modFile].forEach(f => fs.unlink(f.path, () => {}));

    await storage.close();

    res.json({
      mainScreenshotUrl: mainLink,
      screenshotUrls: extraLinks,
      modFileUrl: modLink
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Mega upload backend running on port ${PORT}`);
});