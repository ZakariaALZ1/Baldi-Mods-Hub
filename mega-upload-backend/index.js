// ===== Baldi Mods Hub — Production Secure Backend =====

require('dotenv').config();   // ✅ MUST be first

const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');      // used for download tokens only
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const fsPromises = fs.promises;
const os = require('os');
const { createRemoteJWKSet, jwtVerify } = require('jose');  // JWKS verification
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.set('trust proxy', 1);   // ✅ REQUIRED for Railway + rate limit

app.get('/ping', (req,res)=>res.send("pong"));


/* =========================
   CORS — allow local testing
========================= */

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://zakariaalz1.github.io';
const allowedOrigins = [
  FRONTEND_ORIGIN,
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'http://localhost:8000',
  'http://localhost:8080',
  'null' // ⚠️ for testing from file:// – REMOVE IN PRODUCTION
];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked"));
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-CSRF-Token'],
  credentials: true,
  optionsSuccessStatus: 204
}));

app.use(express.json());

console.log("ENV STATUS", {
  MEGA_EMAIL: !!process.env.MEGA_EMAIL,
  MEGA_PASSWORD: !!process.env.MEGA_PASSWORD,
  DOWNLOAD_SECRET: !!process.env.DOWNLOAD_SECRET,
  SUPABASE_URL: !!process.env.SUPABASE_URL,
  SUPABASE_ANON_KEY: !!process.env.SUPABASE_ANON_KEY
});

/* ================= ENV ================= */

const DOWNLOAD_SECRET = process.env.DOWNLOAD_SECRET;
const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;
const VT_API_KEY = process.env.VT_API_KEY || null;
const SUPABASE_URL = process.env.SUPABASE_URL ? process.env.SUPABASE_URL.replace(/\/$/, '') : null;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!MEGA_EMAIL || !MEGA_PASSWORD || !DOWNLOAD_SECRET || !SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error("❌ Missing required env vars");
  process.exit(1);
}
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
/* ================= CONFIG ================= */

const MAX_SIZE = 100 * 1024 * 1024;
const ALLOWED_EXT = ['.zip','.rar','.7z','.baldimod'];

// In‑memory stores (optional, not used for duplicate prevention)
const moderationQueue = new Map(); // modId → meta
const abuseReports = [];
const bannedIPs = new Set();

/* ================= HELPERS ================= */

function getIP(req){
  return (
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    '0.0.0.0'
  );
}

function cleanup(files){
  files.forEach(f=>f?.path && fs.unlink(f.path,()=>{}));
}

function validExt(name){
  const ext='.'+name.split('.').pop().toLowerCase();
  return ALLOWED_EXT.includes(ext);
}

function sha256File(path){
  return new Promise((resolve,reject)=>{
    const h=crypto.createHash('sha256');
    const s=fs.createReadStream(path);
    s.on('data',d=>h.update(d));
    s.on('end',()=>resolve(h.digest('hex')));
    s.on('error',reject);
  });
}

async function malwareScanHook(path){
  // future: ClamAV hook
  return { clean:true, score:0 };
}

async function virusTotalCheck(hash){
  if(!VT_API_KEY) return {malicious:0,suspicious:0};
  try{
    const r=await axios.get(
      `https://www.virustotal.com/api/v3/files/${hash}`,
      { headers:{'x-apikey':VT_API_KEY}}
    );
    const s=r.data.data.attributes.last_analysis_stats;
    return { malicious:s.malicious, suspicious:s.suspicious };
  }catch{
    return {malicious:0,suspicious:0};
  }
}

async function uploadFile(file,prefix,folder){
  const stats=await fsPromises.stat(file.path);
  const safe=file.originalname.replace(/[^a-zA-Z0-9.-]/g,'_');
  const name=`${prefix}_${Date.now()}_${safe}`;
  const stream=fs.createReadStream(file.path);
  const up = await folder.upload({name,size:stats.size},stream).complete;
  stream.destroy();
  return up;  // returns a File object with nodeId, name, etc.
}

/**
 * Delete a MEGA file by its node ID.
 * This uses the low‑level API because the SDK doesn't expose a direct node‑based delete.
 */
async function deleteMegaFile(nodeId) {
  const storage = await new Storage({
    email: MEGA_EMAIL,
    password: MEGA_PASSWORD
  }).ready;

  const req = {
    a: 'd',                // 'd' = delete
    n: nodeId,             // node handle
    i: storage.api.requestId()
  };

  const response = await storage.api.request(req);
  await storage.close();
  return response;
}

app.use((req,res,next)=>{
  if(bannedIPs.has(getIP(req)))
    return res.status(403).send("IP banned");
  next();
});

app.set('trust proxy', 1);

app.use(rateLimit({
  windowMs: 15*60*1000,
  max: 200
}));

/* ================= SUPABASE JWT VERIFY (JWKS) ================= */

// Custom fetch function with detailed logging
async function fetchWithLogging(url, options) {
  console.log(`[JWKS] Fetching ${url} with headers:`, options?.headers);
  try {
    const response = await fetch(url, options);
    console.log(`[JWKS] Response status: ${response.status} ${response.statusText}`);
    if (!response.ok) {
      const text = await response.text();
      console.log(`[JWKS] Response body (first 200 chars): ${text.slice(0, 200)}`);
    }
    return response;
  } catch (err) {
    console.error(`[JWKS] Fetch error:`, err);
    throw err;
  }
}

// Create a remote JWK set with the API key as a query parameter
const JWKS = createRemoteJWKSet(
  new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json?apikey=${SUPABASE_ANON_KEY}`),
  {
    fetch: async (url, options) => {
      console.log(`[JWKS] Fetching ${url}`);
      try {
        const response = await fetch(url, options);
        console.log(`[JWKS] Response status: ${response.status}`);
        if (!response.ok) {
          const text = await response.text();
          console.log(`[JWKS] Response body (first 200 chars): ${text.slice(0, 200)}`);
        }
        return response;
      } catch (err) {
        console.error('[JWKS] Fetch error:', err);
        throw err;
      }
    }
  }
);

async function verifySupabaseJWT(token) {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `${SUPABASE_URL}/auth/v1`,
      audience: "authenticated"
    });
    return payload;
  } catch (err) {
    console.error("JWT verification failed:", err.message, err.stack);
    throw err;
  }
}

/* ================= AUTH MIDDLEWARE ================= */

async function requireAuth(req,res,next){
  if (req.method === 'OPTIONS') return next();
  try{
    const h = req.headers.authorization;
    if (!h || !h.startsWith("Bearer ")) 
      return res.status(401).json({error:"Missing auth header"});
    const token = h.split(' ')[1];
    console.log("JWT first chars:", token.slice(0,30));
    const payload = await verifySupabaseJWT(token);
    console.log("JWT OK user:", payload.sub);
    req.userId = payload.sub;
    
    // Fetch user's role from profiles table using admin client
    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('role')
      .eq('id', req.userId)
      .single();
    
    if (profileError) {
      console.error("Failed to fetch profile for role:", profileError);
      req.userRole = payload.role || "authenticated"; // fallback
    } else {
      req.userRole = profile.role || "user";
    }
    
    next();
  } catch (e){
    console.error("JWT verify failed FULL:", e.message);
    return res.status(401).json({error:"Invalid token"});
  }
}
/* ================= EXTRA AUTH ================= */

function requireAdmin(req,res,next){
  if(req.userRole !== 'service_role' && req.userRole !== 'admin'){
    return res.status(403).json({error:"Admin only"});
  }
  next();
}

function requireCSRF(req,res,next){
  if (req.method === 'OPTIONS') return next();
  if(!req.headers['x-csrf-token']){
    return res.status(403).json({error:"Missing CSRF"});
  }
  next();
}

app.get('/debug-token', requireAuth, (req,res)=>{
  res.json({
    ok: true,
    user: req.userId,
    role: req.userRole
  });
});

/* ================= MULTER ================= */

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_SIZE }
});

/* ================= UPLOAD ================= */

app.post(
  '/upload',
  requireAuth,
  requireCSRF,
  upload.fields([
    { name: 'mainScreenshot', maxCount: 1 },
    { name: 'screenshots', maxCount: 2 },
    { name: 'modFile', maxCount: 1 }
  ]),
  async (req, res) => {

    const files = [];

    try {
      /* ---------- Required files ---------- */

      if (!req.files?.mainScreenshot || !req.files?.modFile) {
        return res.status(400).json({ error: "Missing required files" });
      }

      files.push(...req.files.mainScreenshot);
      files.push(...req.files.modFile);
      if (req.files.screenshots) files.push(...req.files.screenshots);

      const mod = req.files.modFile[0];

      /* ---------- Extension validation ---------- */

      if (!validExt(mod.originalname)) {
        return res.status(400).json({ error: "Invalid file type" });
      }

      /* ---------- Compute hash ---------- */

      const hash = await sha256File(mod.path);

      /* ---------- Check for duplicate in database ---------- */

      const { data: existing } = await supabaseAdmin
        .from('mods2')
        .select('id')
        .eq('file_hash', hash)
        .maybeSingle();

      if (existing) {
        return res.status(409).json({
          error: "Duplicate file already uploaded"
        });
      }

      /* ---------- Malware scan ---------- */

      const scan = await malwareScanHook(mod.path);
      if (!scan.clean) {
        return res.status(400).json({
          error: "Malware detected"
        });
      }

      /* ---------- VirusTotal ---------- */

      const vt = await virusTotalCheck(hash);

      if (vt.malicious > 0) {
        return res.status(400).json({
          error: "VirusTotal flagged file"
        });
      }

      /* ---------- MEGA upload ---------- */

      const storage = await new Storage({
        email: MEGA_EMAIL,
        password: MEGA_PASSWORD
      }).ready;

      const folder = await storage.mkdir(`mod_${Date.now()}`);

      const main = await uploadFile(
        req.files.mainScreenshot[0],
        'main',
        folder
      );

      const extras = await Promise.all(
        (req.files.screenshots || []).map(f =>
          uploadFile(f, 'extra', folder)
        )
      );

      const modUp = await uploadFile(mod, 'mod', folder);

      const modFileUrl = await modUp.link();
      const mainScreenshotUrl = await main.link();
      const screenshotUrls = await Promise.all(extras.map(x => x.link()));

      /* ---------- Fetch author info ---------- */

      const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('username')
        .eq('id', req.userId)
        .single();

      const authorName = profile?.username || req.userId.split('@')[0] || 'Unknown';
      const fileExt = '.' + mod.originalname.split('.').pop().toLowerCase();

      /* ---------- Insert into Supabase ---------- */

      const modId = crypto.randomUUID();

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
          user_id: req.userId,
          author_name: authorName,
          file_size: mod.size,
          file_extension: fileExt,
          original_filename: mod.originalname,
          screenshots: [
            { url: mainScreenshotUrl, is_main: true, sort_order: 0 },
            ...screenshotUrls.map((url, i) => ({ url, is_main: false, sort_order: i + 1 }))
          ],
          approved: false,
          scan_status: 'pending',
          download_count: 0,
          view_count: 0,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          file_hash: hash
        }]);

      if (dbError) {
        if (dbError.code === '23505') {
          return res.status(409).json({ error: 'Duplicate file already uploaded' });
        }
        throw dbError;
      }

      /* ---------- Optional: keep moderation queue ---------- */
      moderationQueue.set(modId, {
        id: modId,
        user: req.userId,
        hash,
        created: Date.now(),
        status: "pending",
        risk: vt.malicious + vt.suspicious
      });

      /* ---------- Response ---------- */

      const result = {
        modId,
        mainScreenshotUrl,
        screenshotUrls,
        modFileUrl,
        fileHash: hash,
        riskScore: vt.malicious + vt.suspicious,
        moderationStatus: "pending"
      };

      await storage.close();

      cleanup(files);

      return res.json(result);

    } catch (e) {
      console.error("UPLOAD ERROR:", e);

      cleanup(files);

      return res.status(500).json({
        error: e.message || "Upload failed"
      });
    }
  }
);

// ================= ANNOUNCEMENT IMAGE UPLOAD =================
app.post(
  '/upload-announcement-images',
  requireAuth,
  requireAdmin,        // only admins can upload
  upload.array('images', 2),   // accept up to 2 images under field name "images"
  async (req, res) => {
    const files = req.files;
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }

    const tempFiles = []; // track for cleanup
    try {
      const storage = await new Storage({
        email: MEGA_EMAIL,
        password: MEGA_PASSWORD
      }).ready;

      // Create a folder for this batch (or use a persistent folder)
      const folder = await storage.mkdir(`announcement_${Date.now()}`);

      const uploaded = [];
      for (const file of files) {
        tempFiles.push(file);
        const up = await uploadFile(file, 'img', folder);
        const url = await up.link();
        // The uploaded file object has a nodeId (unique identifier)
        uploaded.push({
          url,
          nodeId: up.nodeId,      // MEGA file node ID
          name: up.name
        });
      }

      await storage.close();
      cleanup(tempFiles);

      return res.json({ images: uploaded });

    } catch (err) {
      console.error('Announcement image upload error:', err);
      cleanup(tempFiles);
      return res.status(500).json({ error: err.message });
    }
  }
);

// ================= DELETE MEGA FILE =================
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

/* ================= SIGNED DOWNLOAD ================= */

app.post('/make-download-token', requireAuth, (req,res)=>{
  const {modId,url}=req.body;

  const token=jwt.sign({
    modId,
    url,
    ip:getIP(req),
    ua:req.headers['user-agent']
  }, DOWNLOAD_SECRET, {expiresIn:'5m'});

  res.send(token);
});

app.get('/download/:id',(req,res)=>{
  try{
    const decoded=jwt.verify(req.query.token,DOWNLOAD_SECRET);

    if(decoded.modId !== req.params.id)
      return res.status(403).send("Invalid mod");

    if(decoded.ip !== getIP(req))
      return res.status(403).send("IP mismatch");

    if(decoded.ua !== req.headers['user-agent'])
      return res.status(403).send("UA mismatch");

    res.redirect(decoded.url);

  }catch{
    res.status(403).send("Expired");
  }
});

/* ================= ADMIN ================= */

app.get('/admin/moderation', requireAuth, requireAdmin,
  (req,res)=>res.json([...moderationQueue.values()])
);

app.post('/admin/approve/:id', requireAuth, requireAdmin,
  (req,res)=>{
    const m=moderationQueue.get(req.params.id);
    if(!m) return res.status(404).send("Not found");
    m.status="approved";
    res.json(m);
  });

/* ================= REPORT ================= */

app.post('/report', requireAuth,
  (req,res)=>{
    abuseReports.push({user:req.userId,...req.body,time:Date.now()});
    res.json({ok:true});
  });

/* ================= IP BAN ================= */

app.post('/admin/ban-ip', requireAuth, requireAdmin, (req,res)=>{
  bannedIPs.add(req.body.ip);
  res.json({banned:true});
});

app.post('/admin/unban-ip', requireAuth, requireAdmin, (req,res)=>{
  bannedIPs.delete(req.body.ip);
  res.json({unbanned:true});
});

/* ================= HEALTH ================= */

app.get('/health',(req,res)=>res.send("OK"));

/* ================= START ================= */

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log("✅ Secure backend running on",PORT));