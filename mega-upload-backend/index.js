// mega-upload-backend/index.js
const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());

const upload = multer({ dest: '/tmp/' });

const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;

if (!MEGA_EMAIL || !MEGA_PASSWORD) {
  console.error('❌ Missing Mega credentials in .env');
  process.exit(1);
}

// Helper to add random delay (1-4 seconds)
const randomDelay = () => new Promise(resolve => setTimeout(resolve, Math.floor(Math.random() * 3000) + 1000));

app.post('/upload', upload.fields([
  { name: 'mainScreenshot', maxCount: 1 },
  { name: 'screenshots', maxCount: 4 },
  { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('Upload started...');
    
    // Optional: delay before starting
    await randomDelay();

    const storage = await new Storage({ email: MEGA_EMAIL, password: MEGA_PASSWORD }).ready;
    const folderName = `baldi_mod_${Date.now()}`;
    const uploadFolder = await storage.mkdir(folderName);

    const uploadFile = async (file, prefix) => {
      // Add delay before each file upload
      await randomDelay();
      
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

    const mainFile = req.files['mainScreenshot'][0];
    const mainUpload = await uploadFile(mainFile, 'main');

    const extraFiles = req.files['screenshots'] || [];
    const extraUploads = await Promise.all(extraFiles.map(f => uploadFile(f, 'extra')));

    const modFile = req.files['modFile'][0];
    const modUpload = await uploadFile(modFile, 'mod');

    const mainLink = await mainUpload.link();
    const extraLinks = await Promise.all(extraUploads.map(f => f.link()));
    const modLink = await modUpload.link();

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