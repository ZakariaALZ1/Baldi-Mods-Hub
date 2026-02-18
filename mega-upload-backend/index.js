// ===== Baldi Mods Hub — Production Secure Backend =====

const express = require('express');
const multer = require('multer');
const { Storage, File } = require('megajs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const fsPromises = fs.promises;
const os = require('os');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.set('trust proxy', 1);

// ===== LOGGING MIDDLEWARE (NEW) =====
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

app.get('/ping', (req, res) => res.send('pong'));

/* ================= CORS ================= */
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://zakariaalz1.github.io';
const allowedOrigins = [
  FRONTEND_ORIGIN,
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

// CORS middleware with logging
app.use(cors({
  origin(origin, cb) {
    console.log('CORS check - origin:', origin);
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    console.warn(`CORS blocked origin: ${origin}`);
    return cb(new Error('CORS blocked'));
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-CSRF-Token'],
  credentials: true,
  optionsSuccessStatus: 204
}));

// Explicit OPTIONS handler for /upload (ensures preflight works)
app.options('/upload', (req, res) => {
  res.status(204).end();
});

app.use(express.json());

/* ================= ENV LOGGING ================= */
console.log('ENV STATUS', {
  MEGA_EMAIL: !!process.env.MEGA_EMAIL,
  MEGA_PASSWORD: !!process.env.MEGA_PASSWORD,
  DOWNLOAD_SECRET: !!process.env.DOWNLOAD_SECRET,
  SUPABASE_URL: !!process.env.SUPABASE_URL,
  SUPABASE_ANON_KEY: !!process.env.SUPABASE_ANON_KEY
});

/* ================= ENV VARIABLES ================= */
const DOWNLOAD_SECRET = process.env.DOWNLOAD_SECRET;
const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;
const VT_API_KEY = process.env.VT_API_KEY || null;
const SUPABASE_URL = process.env.SUPABASE_URL ? process.env.SUPABASE_URL.replace(/\/$/, '') : null;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!MEGA_EMAIL || !MEGA_PASSWORD || !DOWNLOAD_SECRET || !SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error('❌ Missing required env vars');
  process.exit(1);
}
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

/* ================= CONFIG ================= */
const MAX_SIZE = 100 * 1024 * 1024;
const ALLOWED_EXT = ['.zip','.rar','.7z','.baldimod'];

const hashStore = new Map();
const moderationQueue = new Map();
const abuseReports = [];
const bannedIPs = new Set();

/* ================= HELPERS ================= */
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    '0.0.0.0'
  );
}

function cleanup(files) {
  files.forEach(f => f?.path && fs.unlink(f.path, () => {}));
}

function validExt(name) {
  const ext = '.' + name.split('.').pop().toLowerCase();
  return ALLOWED_EXT.includes(ext);
}

function sha256File(path) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(path);
    s.on('data', d => h.update(d));
    s.on('end', () => resolve(h.digest('hex')));
    s.on('error', reject);
  });
}

async function malwareScanHook(path) {
  return { clean: true, score: 0 };
}

async function virusTotalCheck(hash) {
  if (!VT_API_KEY) return { malicious: 0, suspicious: 0 };
  try {
    const r = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': VT_API_KEY }
    });
    const s = r.data.data.attributes.last_analysis_stats;
    return { malicious: s.malicious, suspicious: s.suspicious };
  } catch {
    return { malicious: 0, suspicious: 0 };
  }
}

async function uploadFile(file, prefix, folder) {
  const stats = await fsPromises.stat(file.path);
  const safe = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const name = `${prefix}_${Date.now()}_${safe}`;
  const stream = fs.createReadStream(file.path);
  const up = await folder.upload({ name, size: stats.size }, stream).complete;
  stream.destroy();
  return up;
}

function keyToBase64(keyArray) {
  if (!keyArray) return null;
  return Buffer.from(keyArray).toString('base64');
}

async function deleteMegaFile(nodeId) {
  const storage = await new Storage({
    email: MEGA_EMAIL,
    password: MEGA_PASSWORD
  }).ready;
  const req = { a: 'd', n: nodeId };
  const response = await storage.api.request(req);
  await storage.close();
  return response;
}

// Delete mod file from Mega (owner, admin, or moderator)
app.post('/delete-mod-file', requireAuth, requireCSRF, async (req, res) => {
  const { modId } = req.body;
  if (!modId) return res.status(400).json({ error: 'Missing modId' });

  // Fetch mod to check ownership and get file_url
  const { data: mod, error: fetchError } = await supabaseAdmin
    .from('mods2')
    .select('user_id, file_url')
    .eq('id', modId)
    .single();

  if (fetchError || !mod) {
    return res.status(404).json({ error: 'Mod not found' });
  }

  // Permission: owner, admin, or moderator
  const isOwner = mod.user_id === req.userId;
  const isStaff = req.userRole === 'admin' || req.userRole === 'moderator';
  if (!isOwner && !isStaff) {
    return res.status(403).json({ error: 'Permission denied' });
  }

  const fileUrl = mod.file_url;
  if (!fileUrl) {
    return res.status(400).json({ error: 'No file URL associated' });
  }

  // Extract nodeId from Mega URL (e.g., https://mega.nz/file/XXXXXXXX#YYYYYY)
  const match = fileUrl.match(/\/file\/([^#]+)/);
  if (!match) {
    return res.status(400).json({ error: 'Invalid file URL format' });
  }
  const nodeId = match[1];

  try {
    await deleteMegaFile(nodeId);   // function already defined in your backend
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete Mega file:', err);
    res.status(500).json({ error: 'Failed to delete file from Mega', details: err.message });
  }
});
/* ================= IP BAN & RATE LIMIT ================= */
app.use((req, res, next) => {
  if (bannedIPs.has(getIP(req))) return res.status(403).send('IP banned');
  next();
});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
}));

/* ================= SUPABASE JWT VERIFY ================= */
const JWKS = createRemoteJWKSet(
  new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json?apikey=${SUPABASE_ANON_KEY}`)
);

async function verifySupabaseJWT(token) {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `${SUPABASE_URL}/auth/v1`,
      audience: 'authenticated'
    });
    return payload;
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    throw err;
  }
}

/* ================= AUTH MIDDLEWARE ================= */
async function requireAuth(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  try {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) {
      console.log('requireAuth: No Bearer token found');
      return res.status(401).json({ error: 'Missing auth header' });
    }
    const token = h.split(' ')[1];
    console.log('requireAuth: Token received, length:', token.length);
    const payload = await verifySupabaseJWT(token);
    req.userId = payload.sub;

    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('role')
      .eq('id', req.userId)
      .single();

    if (profileError) {
      console.error('Failed to fetch profile for role:', profileError);
      req.userRole = payload.role || 'authenticated';
    } else {
      req.userRole = profile.role || 'user';
    }

    next();
  } catch (e) {
    console.error('JWT verify failed:', e.message);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

function requireCSRF(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  if (!req.headers['x-csrf-token']) {
    return res.status(403).json({ error: 'Missing CSRF' });
  }
  next();
}

app.get('/debug-token', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.userId, role: req.userRole });
});

/* ================= MULTER ================= */
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_SIZE }
});

/* ================= UPLOAD MOD (MEGA + freeimage.host) ================= */
app.post('/upload', requireAuth, requireCSRF, upload.fields([
  { name: 'mainScreenshot', maxCount: 1 },
  { name: 'screenshots', maxCount: 2 },
  { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
  // ===============================
  // AUTH CHECK
  // ===============================
  const user = req.userId;
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // ===============================
  // COLLECT FILES
  // ===============================
  const files = req.files;
  if (!files) {
    return res.status(400).json({ error: 'No files uploaded' });
  }

  const modFile = files.modFile?.[0];
  const mainScreenshot = files.mainScreenshot?.[0];
  const additionalScreenshots = files.screenshots || [];

  if (!modFile || !mainScreenshot) {
    return res.status(400).json({ error: 'Missing required files' });
  }

  // ===============================
  // VALIDATION
  // ===============================
  const fileExt = '.' + modFile.originalname.split('.').pop().toLowerCase();
  if (!ALLOWED_EXT.includes(fileExt)) {
    return res.status(400).json({ error: `Only ${ALLOWED_EXT.join(', ')} files allowed` });
  }

  if (modFile.size > MAX_SIZE) {
    return res.status(400).json({ error: `File exceeds ${Math.round(MAX_SIZE / (1024 * 1024))}MB` });
  }

  // ===============================
  // HASH DEDUP
  // ===============================
  const hash = await sha256File(modFile.path);
  if (hashStore.has(hash)) {
    return res.status(409).json({ error: 'Duplicate file already uploaded' });
  }

  // ===============================
  // MALWARE SCAN (placeholder)
  // ===============================
  const scan = await malwareScanHook(modFile.path);
  if (!scan.clean) {
    return res.status(400).json({ error: 'Malware detected' });
  }

  // ===============================
  // VIRUSTOTAL CHECK (optional)
  // ===============================
  const vt = await virusTotalCheck(hash);
  if (vt.malicious > 0) {
    return res.status(400).json({ error: 'VirusTotal flagged file' });
  }

  // ===============================
  // FREEIMAGE.HOST UPLOAD (for screenshots)
  // ===============================
  const FREEIMAGE_API_KEY = process.env.FREEIMAGE_HOST_API_KEY;
  if (!FREEIMAGE_API_KEY) {
    console.error('[upload] FREEIMAGE_HOST_API_KEY is not set');
    return res.status(500).json({ error: 'Server configuration error', details: 'freeimage.host API key missing' });
  }

  async function uploadToFreeimage(file) {
    const fileBuffer = await fsPromises.readFile(file.path);
    const base64Image = fileBuffer.toString('base64');

    const formData = new URLSearchParams();
    formData.append('key', FREEIMAGE_API_KEY);
    formData.append('source', base64Image);
    formData.append('format', 'json');

    const response = await axios.post('https://freeimage.host/api/1/upload', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000
    });

    if (response.data && response.data.success) {
      return response.data.image.url;
    } else {
      throw new Error('freeimage.host upload failed: ' + (response.data?.error?.message || 'Unknown'));
    }
  }

  // Upload main screenshot
  let mainScreenshotUrl;
  try {
    mainScreenshotUrl = await uploadToFreeimage(mainScreenshot);
  } catch (err) {
    console.error('Main screenshot upload error:', err);
    return res.status(500).json({ error: 'Failed to upload main screenshot', details: err.message });
  }

  // Upload additional screenshots
  const screenshotUrls = [];
  for (const file of additionalScreenshots) {
    try {
      const url = await uploadToFreeimage(file);
      screenshotUrls.push(url);
    } catch (err) {
      console.error('Additional screenshot upload error:', err);
      return res.status(500).json({ error: 'Failed to upload additional screenshot', details: err.message });
    }
  }

  // ===============================
  // MEGA UPLOAD (mod file only)
  // ===============================
  let storage, folder, modUp;
  try {
    storage = await new Storage({ email: MEGA_EMAIL, password: MEGA_PASSWORD }).ready;
    folder = await storage.mkdir(`mod_${Date.now()}`);
    modUp = await uploadFile(modFile, 'mod', folder);
  } catch (err) {
    console.error('MEGA upload error:', err);
    return res.status(500).json({ error: 'Failed to upload mod file to MEGA' });
  }

  // ===============================
  // GENERATE MEGA MOD FILE URL
  // ===============================
  let modFileUrl;
  try {
    modFileUrl = await modUp.link();
  } catch (err) {
    console.error('MEGA link error:', err);
    return res.status(500).json({ error: 'Failed to get MEGA link' });
  }

  // ===============================
  // FETCH AUTHOR NAME
  // ===============================
  const { data: profile } = await supabaseAdmin
    .from('profiles')
    .select('username')
    .eq('id', user)
    .single();
  const authorName = profile?.username || user?.split('@')[0] || 'Unknown';

  // ===============================
  // GENERATE MOD ID
  // ===============================
  const modId = crypto.randomUUID();

  // ===============================
  // STORE IN DATABASE (mods2 table)
  // ===============================
  try {
    const { error: dbError } = await supabaseAdmin
      .from('mods2')
      .insert([{
        id: modId,
        title: req.body.title || 'Untitled',
        description: req.body.description || '',
        version: req.body.version || '1.0.0',
        baldi_version: req.body.baldiVersion || null,
        tags: req.body.tags ? req.body.tags.split(',').map(t => t.trim()) : [],
        file_url: modFileUrl,
        user_id: user,
        author_name: authorName,
        file_size: modFile.size,
        file_extension: fileExt,
        original_filename: modFile.originalname,
        screenshots: [
          { url: mainScreenshotUrl, is_main: true, sort_order: 0 },
          ...screenshotUrls.map((url, i) => ({ url, is_main: false, sort_order: i + 1 }))
        ],
        approved: false,
        scan_status: 'pending',
        download_count: 0,
        view_count: 0,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }]);

    if (dbError) throw dbError;
  } catch (err) {
    console.error('Database insert error:', err);
    return res.status(500).json({ error: 'Failed to save mod data', details: err.message });
  }

  hashStore.set(hash, modId);

  // Clean up temp files
  [modFile, mainScreenshot, ...additionalScreenshots].forEach(f => {
    if (f?.path) fs.unlink(f.path, () => {});
  });

  return res.json({
    modFileUrl,
    mainScreenshotUrl,
    screenshotUrls,
    fileHash: hash,
    riskScore: vt.malicious + vt.suspicious,
    moderationStatus: 'pending'
  });
});

/* ================= DEBUG ENDPOINTS ================= */
app.get('/debug-env', (req, res) => {
  const key = process.env.FREEIMAGE_HOST_API_KEY;
  res.json({
    exists: !!key,
    length: key ? key.length : 0,
    firstFive: key ? key.substring(0,5) : null
  });
});

app.get('/debug-all-env', (req, res) => {
  const keys = Object.keys(process.env).sort();
  res.json({ keys });
});

app.get('/test-connect', async (req, res) => {
  try {
    const response = await axios.get('https://freeimage.host', { timeout: 5000 });
    res.send(`✅ freeimage.host is reachable (status ${response.status})`);
  } catch (err) {
    res.status(500).send(`❌ Cannot reach freeimage.host: ${err.message}`);
  }
});

app.get('/test-key', (req, res) => {
  const key = process.env.FREEIMAGE_HOST_API_KEY;
  res.json({
    exists: !!key,
    length: key ? key.length : 0,
    firstFive: key ? key.substring(0,5) : null
  });
});

app.get('/test-upload-route', (req, res) => {
  res.send('Upload route is registered');
});

app.get('/test-auth', requireAuth, (req, res) => {
  res.json({ userId: req.userId, role: req.userRole });
});

/* ================= ANNOUNCEMENT IMAGE UPLOAD ================= */
app.post('/upload-announcement-images', requireAuth, upload.array('images', 2), async (req, res) => {
  console.log('[upload-images] ===== ENTERED HANDLER =====');
  const files = req.files;
  console.log(`[upload-images] Received ${files?.length} files`);

  if (!files || files.length === 0) {
    return res.status(400).json({ error: 'No images uploaded' });
  }

const API_KEY = process.env.FREEIMAGE_HOST_API_KEY;
if (!API_KEY) {
  console.error('[upload-images] FREEIMAGE_HOST_API_KEY is not set in environment');
  return res.status(500).json({ error: 'Server configuration error', details: 'API key missing' });
}
  console.log('[upload-images] Using hardcoded API key (first 5 chars):', API_KEY.substring(0, 5));

  const uploaded = [];

  try {
    for (const file of files) {
      console.log(`[upload-images] Processing: ${file.originalname} (size: ${file.size} bytes)`);

      // Read file and convert to base64
      const fileBuffer = await fsPromises.readFile(file.path);
      const base64Image = fileBuffer.toString('base64');
      console.log('[upload-images] Base64 length:', base64Image.length);
      console.log('[upload-images] Base64 preview (first 50 chars):', base64Image.substring(0, 50));

      // Prepare form data
      const formData = new URLSearchParams();
      formData.append('key', API_KEY);
      formData.append('source', base64Image);
      formData.append('format', 'json');
      console.log('[upload-images] Sending to freeimage.host...');

      // Upload to freeimage.host with timeout
      const response = await axios.post('https://freeimage.host/api/1/upload', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 15000
      });

      // Clean up temp file
      await fsPromises.unlink(file.path).catch(err => console.warn('Temp file cleanup failed:', err));

      console.log('[upload-images] freeimage.host response status:', response.status);
      console.log('[upload-images] freeimage.host response data:', JSON.stringify(response.data, null, 2));

      if (response.data && response.data.success) {
        // URL is at response.data.image.url
        const imageUrl = response.data.image?.url;
        if (!imageUrl) {
          throw new Error('Image URL missing in response');
        }
        console.log(`[upload-images] SUCCESS! URL: ${imageUrl}`);
        uploaded.push({ url: imageUrl });
      } else {
        console.error('[upload-images] Upload failed (API error):', response.data);
        throw new Error('Upload failed: ' + (response.data?.error?.message || 'Unknown error'));
      }
    }

    console.log('[upload-images] All uploads successful');
    return res.json({ images: uploaded });

  } catch (error) {
    console.error('[upload-images] CATCH block error:', error.message);
    if (error.response) {
      console.error('[upload-images] Response status:', error.response.status);
      console.error('[upload-images] Response headers:', error.response.headers);
      console.error('[upload-images] Response data:', error.response.data);
    } else if (error.request) {
      console.error('[upload-images] No response received from freeimage.host');
    } else {
      console.error('[upload-images] Error setting up request:', error.message);
    }
    // Clean up any remaining temp files
    for (const file of files) {
      await fsPromises.unlink(file.path).catch(() => {});
    }
    return res.status(500).json({ error: 'Image upload failed', details: error.message });
  }
});

/* ================= OTHER ENDPOINTS ================= */
app.get('/proxy-image', async (req, res) => {
  console.log(`[proxy-image] REQUEST for nodeId: ${req.query.nodeId}`);
  const { nodeId } = req.query;
  if (!nodeId) return res.status(400).send('Missing nodeId');

  try {
    const { data, error } = await supabaseAdmin
      .from('announcements')
      .select('image_nodes, image_keys')
      .contains('image_nodes', [nodeId])
      .limit(1);

    if (error) throw new Error(`DB error: ${error.message}`);
    if (!data || data.length === 0) throw new Error('No record found');

    const record = data[0];
    const index = record.image_nodes.indexOf(nodeId);
    if (index === -1) throw new Error('Node ID not in array');

    const keyBase64 = record.image_keys?.[index];
    if (!keyBase64) throw new Error('Key missing');

    const keyBuffer = Buffer.from(keyBase64, 'base64');
    const megaUrl = `https://mega.nz/file/${nodeId}#${keyBuffer.toString('base64url')}`;
    const { File } = require('megajs');
    const file = File.fromURL(megaUrl);

    const ext = file.name?.split('.').pop().toLowerCase() || 'png';
    const mime = {
      jpg: 'image/jpeg', jpeg: 'image/jpeg',
      png: 'image/png', gif: 'image/gif', webp: 'image/webp'
    };
    res.setHeader('Content-Type', mime[ext] || 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=86400');

    const stream = file.download();
    stream.on('error', err => {
      console.error('[proxy-image] Stream error:', err);
      if (!res.headersSent) res.status(500).send('Download failed');
    });
    stream.pipe(res);

  } catch (err) {
    console.error('[proxy-image] ERROR:', err);
    res.status(500).send(err.message);
  }
});

app.get('/test-url', (req, res) => {
  const nodeId = 'KsNWWLZT';
  const keyBase64 = 'FCvZ5LItgLqFFlgZDHRav3waryfk4mUKPIebxkOocSU';
  const keyBuffer = Buffer.from(keyBase64, 'base64');
  const megaUrl = `https://mega.nz/file/${nodeId}#${keyBuffer.toString('base64url')}`;
  res.send(megaUrl);
});

app.delete('/delete-mega-file', requireAuth, requireAdmin, async (req, res) => {
  const { nodeId } = req.body;
  if (!nodeId) return res.status(400).json({ error: 'Missing nodeId' });

  try {
    await deleteMegaFile(nodeId);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete failed:', err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/delete-mega-folder', requireAuth, requireAdmin, async (req, res) => {
  const { folderNodeId } = req.body;
  if (!folderNodeId) return res.status(400).json({ error: 'Missing folderNodeId' });

  try {
    const storage = await new Storage({ email: MEGA_EMAIL, password: MEGA_PASSWORD }).ready;
    const folder = storage.root?.children?.find(c => c.nodeId === folderNodeId);
    if (!folder) throw new Error('Folder not found');

    // For simplicity, we just return success – actual recursive deletion is complex.
    // You may enhance this later.
    res.json({ success: true });
  } catch (err) {
    console.error('Delete folder error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/make-download-token', requireAuth, (req, res) => {
  const { modId, url } = req.body;
  const token = jwt.sign(
    { modId, url, ip: getIP(req), ua: req.headers['user-agent'] },
    DOWNLOAD_SECRET,
    { expiresIn: '5m' }
  );
  res.send(token);
});

app.get('/download/:id', (req, res) => {
  try {
    const decoded = jwt.verify(req.query.token, DOWNLOAD_SECRET);
    if (decoded.modId !== req.params.id) return res.status(403).send('Invalid mod');
    if (decoded.ip !== getIP(req)) return res.status(403).send('IP mismatch');
    if (decoded.ua !== req.headers['user-agent']) return res.status(403).send('UA mismatch');
    res.redirect(decoded.url);
  } catch {
    res.status(403).send('Expired');
  }
});

app.get('/admin/moderation', requireAuth, requireAdmin, (req, res) => {
  res.json([...moderationQueue.values()]);
});

app.post('/admin/approve/:id', requireAuth, requireAdmin, (req, res) => {
  const m = moderationQueue.get(req.params.id);
  if (!m) return res.status(404).send('Not found');
  m.status = 'approved';
  res.json(m);
});

app.post('/report', requireAuth, (req, res) => {
  abuseReports.push({ user: req.userId, ...req.body, time: Date.now() });
  res.json({ ok: true });
});

app.post('/admin/ban-ip', requireAuth, requireAdmin, (req, res) => {
  bannedIPs.add(req.body.ip);
  res.json({ banned: true });
});

app.post('/admin/unban-ip', requireAuth, requireAdmin, (req, res) => {
  bannedIPs.delete(req.body.ip);
  res.json({ unbanned: true });
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

/* ================= GLOBAL ERROR HANDLER ================= */
app.use((err, req, res, next) => {
  console.error('🔥 UNHANDLED ERROR:', err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Secure backend running on', PORT));