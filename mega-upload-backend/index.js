// mega-upload-backend/index.js

const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const fsPromises = fs.promises;
const os = require('os');
require('dotenv').config();

const app = express();

/* =========================
   CONFIG
========================= */

const FRONTEND_ORIGIN = 'https://zakariaalz1.github.io';

const ALLOWED_EXT = ['.zip', '.rar', '.7z', '.baldimod'];
const MAX_SIZE = 100 * 1024 * 1024;

/* =========================
   CORS
========================= */

app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* =========================
   RATE LIMIT
========================= */

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many uploads — try later" }
});

/* =========================
   MULTER
========================= */

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_SIZE }
});

/* =========================
   ENV CHECK
========================= */

const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;

if (!MEGA_EMAIL || !MEGA_PASSWORD) {
  console.error('Missing MEGA credentials');
  process.exit(1);
}

/* =========================
   SUPABASE TOKEN VERIFY
========================= */

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Missing auth header" });

    const token = header.split(' ')[1];
    const decoded = jwt.decode(token);

    if (!decoded || !decoded.sub) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.userId = decoded.sub;
    next();

  } catch {
    res.status(401).json({ error: "Auth failed" });
  }
}

/* =========================
   HELPERS
========================= */

function cleanup(files) {
  files.forEach(f => {
    if (f?.path) fs.unlink(f.path, () => {});
  });
}

function validateExt(name) {
  const ext = '.' + name.split('.').pop().toLowerCase();
  return ALLOWED_EXT.includes(ext);
}

async function uploadFile(file, prefix, folder) {
  const stats = await fsPromises.stat(file.path);
  const safe = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const name = `${prefix}_${Date.now()}_${safe}`;
  const stream = fs.createReadStream(file.path);

  const uploaded = await folder.upload({
    name,
    size: stats.size
  }, stream).complete;

  stream.destroy();
  return uploaded;
}

/* =========================
   ROUTE
========================= */

app.post('/upload', uploadLimiter, requireAuth, (req, res) => {

  const mw = upload.fields([
    { name: 'mainScreenshot', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 },
    { name: 'modFile', maxCount: 1 }
  ]);

  mw(req, res, async err => {

    if (err) return res.status(400).json({ error: err.message });

    const files = [];
    try {

      if (!req.files?.mainScreenshot || !req.files?.modFile) {
        throw new Error("Missing required files");
      }

      files.push(...req.files.mainScreenshot);
      files.push(...req.files.modFile);
      if (req.files.screenshots) files.push(...req.files.screenshots);

      if (!validateExt(req.files.modFile[0].originalname)) {
        throw new Error("Invalid mod file type");
      }

      console.log("Auth user:", req.userId);

      const storage = await new Storage({
        email: MEGA_EMAIL,
        password: MEGA_PASSWORD
      }).ready;

      const folder = await storage.mkdir(`mod_${Date.now()}`);

      const main = await uploadFile(req.files.mainScreenshot[0], 'main', folder);

      const extras = await Promise.all(
        (req.files.screenshots || []).map(f =>
          uploadFile(f, 'extra', folder)
        )
      );

      const mod = await uploadFile(req.files.modFile[0], 'mod', folder);

      const result = {
        mainScreenshotUrl: await main.link(),
        screenshotUrls: await Promise.all(extras.map(x => x.link())),
        modFileUrl: await mod.link()
      };

      await storage.close();
      cleanup(files);

      res.json(result);

    } catch (e) {
      cleanup(files);
      res.status(500).json({ error: e.message });
    }
  });
});

/* =========================
   HEALTH
========================= */

app.get('/health', (req,res)=>res.send('OK'));

app.listen(process.env.PORT || 3000, () =>
  console.log("Backend running")
);


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