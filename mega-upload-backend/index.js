// ===== Baldi Mods Hub — Production Secure Backend =====

const express = require('express');
const multer = require('multer');
const { Storage } = require('megajs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const fsPromises = fs.promises;
const os = require('os');
require('dotenv').config();
const { createRemoteJWKSet, jwtVerify } = require('jose');

const app = express();

const allowedOrigins = [
  'https://zakariaalz1.github.io',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

app.use(cors({
  origin: function (origin, callback) {
    // allow no-origin requests (like curl, server-to-server)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('CORS blocked'));
    }
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-CSRF-Token'],
  credentials: true,
  maxAge: 86400
}));

app.options('/*', cors());
app.use(express.json());

/* ================= ENV ================= */

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';
const DOWNLOAD_SECRET = process.env.DOWNLOAD_SECRET;
const MEGA_EMAIL = process.env.MEGA_EMAIL;
const MEGA_PASSWORD = process.env.MEGA_PASSWORD;
const VT_API_KEY = process.env.VT_API_KEY || null;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!MEGA_EMAIL || !MEGA_PASSWORD || !DOWNLOAD_SECRET || !SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error("❌ Missing required env vars");
  process.exit(1);
}

/* ================= CONFIG ================= */

const MAX_SIZE = 100 * 1024 * 1024;
const ALLOWED_EXT = ['.zip','.rar','.7z','.baldimod'];

const hashStore = new Map();       // hash → modId
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
  const up=await folder.upload({name,size:stats.size},stream).complete;
  stream.destroy();
  return up;
}


/* ================= SUPABASE JWT VERIFY ================= */

const JWKS = createRemoteJWKSet(
  new URL(`${SUPABASE_URL}/auth/v1/jwks`),
  { headers: { apikey: SUPABASE_ANON_KEY } }
);

async function verifySupabaseJWT(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: `${SUPABASE_URL}/auth/v1`,
    audience: "authenticated"
  });
  return payload;
}
/* ================= SECURITY ================= */

app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods:['GET','POST','OPTIONS'],
  allowedHeaders:['Content-Type','Authorization','X-CSRF-Token']
}));

app.use((req,res,next)=>{
  if(bannedIPs.has(getIP(req)))
    return res.status(403).send("IP banned");
  next();
});

app.use(rateLimit({
  windowMs: 15*60*1000,
  max: 200
}));

async function requireAuth(req,res,next){
  try{
    const h = req.headers.authorization;
    if (!h) return res.status(401).json({error:"Missing auth"});

    const token = h.split(' ')[1];

    const payload = await verifySupabaseJWT(token);

    req.userId = payload.sub;
    req.userRole = payload.role || "authenticated";

    next();

  } catch (e){
    console.error("JWT verify failed:", e.message);
    res.status(401).json({error:"Invalid token"});
  }
}


function requireAdmin(req,res,next){
  if(req.userRole !== 'service_role' && req.userRole !== 'admin')
    return res.status(403).json({error:"Admin only"});
  next();
}

function requireCSRF(req,res,next){
  if(!req.headers['x-csrf-token'])
    return res.status(403).json({error:"Missing CSRF"});
  next();
}

/* ================= MULTER ================= */

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_SIZE }
});

/* ================= UPLOAD ================= */

app.post('/upload',
  requireAuth,
  requireCSRF,
  upload.fields([
    {name:'mainScreenshot',maxCount:1},
    {name:'screenshots',maxCount:2},
    {name:'modFile',maxCount:1}
  ]),
async (req,res)=>{

  const files=[];
  try{

    if(!req.files?.mainScreenshot || !req.files?.modFile)
      throw new Error("Missing files");

    files.push(...req.files.mainScreenshot, ...req.files.modFile);
    if(req.files.screenshots) files.push(...req.files.screenshots);

    const mod=req.files.modFile[0];

    if(!validExt(mod.originalname))
      throw new Error("Invalid file type");

    const hash=await sha256File(mod.path);

    if(hashStore.has(hash))
      throw new Error("Duplicate file already uploaded");

    const scan=await malwareScanHook(mod.path);
    if(!scan.clean) throw new Error("Malware detected");

    const vt=await virusTotalCheck(hash);
    if(vt.malicious>0) throw new Error("VirusTotal flagged file");

    const storage = await new Storage({
      email:MEGA_EMAIL,
      password:MEGA_PASSWORD
    }).ready;

    const folder = await storage.mkdir(`mod_${Date.now()}`);

    const main = await uploadFile(req.files.mainScreenshot[0],'main',folder);
    const extras = await Promise.all(
      (req.files.screenshots||[]).map(f=>uploadFile(f,'extra',folder))
    );
    const modUp = await uploadFile(mod,'mod',folder);

    const modId = crypto.randomUUID();

    moderationQueue.set(modId,{
      id:modId,
      user:req.userId,
      hash,
      created:Date.now(),
      status:"pending",
      risk: vt.malicious + vt.suspicious
    });

    hashStore.set(hash,modId);

    const result={
      modId,
      mainScreenshotUrl: await main.link(),
      screenshotUrls: await Promise.all(extras.map(x=>x.link())),
      modFileUrl: await modUp.link(),
      fileHash: hash,
      riskScore: vt.malicious + vt.suspicious,
      moderationStatus:"pending"
    };

    await storage.close();
    cleanup(files);
    res.json(result);

  }catch(e){
    cleanup(files);
    res.status(500).json({error:e.message});
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

app.post('/admin/ban-ip', requireAuth, requireAdmin,
  (req,res)=>{
    bannedIPs.add(req.body.ip);
    res.json({banned:true});
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
