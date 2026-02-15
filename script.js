(function() {
  // ===== DUPLICATE SCRIPT GUARD =====
  if (window.__SUPABASE_INIT_DONE__) {
    console.log("Supabase already initialized – skipping duplicate script.");
    return;
  }
  window.__SUPABASE_INIT_DONE__ = true;

  /* =========================
     SUPABASE INIT
  ========================= */
  (function() {
    if (typeof window.supabase === 'undefined' || typeof window.supabase.createClient !== 'function') {
      console.error('❌ Supabase library not loaded or invalid!');
      return;
    }
    const SUPABASE_URL = window.ENV?.SUPABASE_URL || "https://mxecvkhtleecopiqqloh.supabase.co";
    const SUPABASE_ANON_KEY = window.ENV?.SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im14ZWN2a2h0bGVlY29waXFxbG9oIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzEwNDA3MzksImV4cCI6MjA4NjYxNjczOX0.oYrRPY0uQWSwzaScjPRlXJja6M2a69TJ72-Whjb4rPM";
    if (!window.__SUPABASE_CLIENT__) {
      window.__SUPABASE_CLIENT__ = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    }
  })();

  window.supabaseClient = window.__SUPABASE_CLIENT__;
  const supabaseClient = window.__SUPABASE_CLIENT__;

  /* =========================
     MEGA BACKEND URL
  ========================= */
  const MEGA_BACKEND_URL = 'https://baldi-mods-hub-production.up.railway.app/upload';

  /* =========================
     GLOBAL STATE MANAGEMENT
  ========================= */
  let currentUser = null;
  let currentUserProfile = null;
  let currentUserRole = null;
  let isAuthenticated = false;
  let sessionCheckInterval = null;
  let inactivityTimer = null;
  let csrfToken = null;

  /* =========================
     SECURITY HELPERS
  ========================= */
  function generateCSRFToken() {
    csrfToken = crypto.randomUUID?.() || Math.random().toString(36).substring(2);
    sessionStorage.setItem('csrf_token', csrfToken);
    return csrfToken;
  }
  function validateCSRFToken(token) {
    const stored = sessionStorage.getItem('csrf_token');
    return stored && token === stored;
  }
  function sanitizeInput(str) {
    if (!str) return '';
    return str
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/on\w+="[^"]*"/gi, '')
      .replace(/javascript:/gi, '')
      .trim();
  }
  function resetInactivityTimer() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(async () => {
      if (isAuthenticated) {
        await logout();
        showNotification('Session expired due to inactivity', 'info');
      }
    }, 3600000);
  }
  ['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
    document.addEventListener(event, resetInactivityTimer);
  });

  /* =========================
     GAMEBANANA STYLE NOTIFICATIONS
  ========================= */
  function showNotification(message, type = 'info', duration = 5000) {
    const existing = document.querySelectorAll('.gb-notification');
    existing.forEach(n => n.remove());
    const notification = document.createElement('div');
    notification.className = `gb-notification gb-${type}`;
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    notification.innerHTML = `
      <div class="gb-notification-icon">${icons[type] || '📢'}</div>
      <div class="gb-notification-content">${message}</div>
      <button class="gb-notification-close">×</button>
    `;
    notification.style.cssText = `
      position: fixed; top: 20px; right: 20px; width: 320px; padding: 16px 20px;
      background: ${type === 'error' ? '#2d1a1a' : type === 'success' ? '#1a2d1a' : type === 'warning' ? '#2d2d1a' : '#1a1a2d'};
      border-left: 4px solid ${type === 'error' ? '#ff4444' : type === 'success' ? '#00ff88' : type === 'warning' ? '#ffaa00' : '#2196f3'};
      color: white; border-radius: 8px; box-shadow: 0 8px 20px rgba(0,0,0,0.3); z-index: 99999;
      display: flex; align-items: center; gap: 12px; font-family: 'Segoe UI', Arial, sans-serif;
      animation: gbSlideIn 0.3s ease;
    `;
    document.body.appendChild(notification);
    notification.querySelector('.gb-notification-close').onclick = () => {
      notification.style.animation = 'gbSlideOut 0.3s ease';
      setTimeout(() => notification.remove(), 300);
    };
    setTimeout(() => {
      if (notification.parentNode) {
        notification.style.animation = 'gbSlideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
      }
    }, duration);
  }

  const style = document.createElement('style');
  style.textContent = `
    @keyframes gbSlideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    @keyframes gbSlideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
    @keyframes gbSpin { to { transform: rotate(360deg); } }
    .gb-loading-spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: #00ff88; border-radius: 50%; animation: gbSpin 0.8s linear infinite; margin-right: 8px; }
    .gb-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; margin-left: 8px; }
    .gb-badge.admin { background: #ff4444; color: white; }
    .gb-badge.moderator { background: #ffaa00; color: black; }
    .gb-badge.verified { background: #00ff88; color: black; }
    .gb-badge.premium { background: #aa80ff; color: white; }
    .gb-card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 20px; transition: all 0.2s; }
    .gb-card:hover { border-color: #00ff88; transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,255,136,0.1); }
    .gb-btn { padding: 10px 20px; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; transition: all 0.2s; }
    .gb-btn-primary { background: #00ff88; color: black; }
    .gb-btn-primary:hover { background: #00cc66; transform: translateY(-2px); }
    .gb-btn-danger { background: #ff4444; color: white; }
    .gb-btn-warning { background: #ffaa00; color: black; }
    .gb-btn-secondary { background: #333; color: white; }
    .gb-nav-container { display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }
    .gb-nav-item { color: white; text-decoration: none; padding: 8px 16px; border-radius: 5px; }
    .gb-nav-item:hover { background: #333; }
    .gb-nav-item.active { background: #00ff88; color: black; }
    .gb-nav-disabled { color: #666; padding: 8px 16px; cursor: not-allowed; opacity: 0.7; }
    .gb-nav-user { margin-left: auto; display: flex; align-items: center; gap: 10px; }
    .gb-nav-points { background: #333; padding: 4px 12px; border-radius: 20px; color: #00ff88; font-size: 12px; }
    .gb-profile-container { max-width: 1200px; margin: 0 auto; padding: 20px; display: grid; grid-template-columns: 300px 1fr; gap: 30px; }
    .gb-profile-sidebar { background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; }
    .gb-profile-avatar { text-align: center; margin-bottom: 20px; }
    .gb-avatar { width: 120px; height: 120px; background: linear-gradient(45deg, #00ff88, #00cc66); border-radius: 50%; margin: 0 auto; display: flex; align-items: center; justify-content: center; font-size: 48px; font-weight: bold; color: black; }
    .gb-stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; padding: 20px 0; border-top: 1px solid #333; border-bottom: 1px solid #333; }
    .gb-stat { text-align: center; }
    .gb-stat-value { display: block; font-size: 24px; font-weight: bold; color: #00ff88; }
    .gb-stat-label { font-size: 12px; color: #ccc; }
    .gb-trust-score { margin: 20px 0; }
    .gb-trust-label { display: flex; justify-content: space-between; margin-bottom: 5px; }
    .gb-trust-bar { height: 8px; background: #333; border-radius: 4px; overflow: hidden; }
    .gb-trust-fill { height: 100%; border-radius: 4px; transition: width 0.3s ease; }
    .gb-trust-value { text-align: right; margin-top: 5px; font-weight: bold; }
    .gb-profile-bio { margin-top: 20px; }
    .gb-profile-bio h3 { color: #00ff88; margin-bottom: 10px; }
    .gb-profile-bio p { color: #ccc; line-height: 1.6; }
    .gb-profile-main { background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; }
    .gb-tabs { display: flex; gap: 10px; margin-bottom: 30px; border-bottom: 1px solid #333; padding-bottom: 10px; }
    .gb-tab { padding: 10px 20px; background: transparent; color: #ccc; border: none; cursor: pointer; font-size: 16px; }
    .gb-tab.active { color: #00ff88; border-bottom: 2px solid #00ff88; }
    .gb-tab-content { display: none; }
    .gb-tab-content.active { display: block; }
    .gb-stats-detailed { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-top: 20px; }
    .gb-stat-card { background: #222; padding: 20px; border-radius: 8px; display: flex; align-items: center; gap: 15px; }
    .gb-stat-icon { font-size: 32px; }
    .gb-stat-info { flex: 1; }
    .gb-stat-number { font-size: 24px; font-weight: bold; color: #00ff88; }
    .gb-settings-form { max-width: 500px; }
    .gb-form-group { margin-bottom: 20px; }
    .gb-form-group label { display: block; margin-bottom: 5px; color: #ccc; }
    .gb-form-group input, .gb-form-group textarea { width: 100%; padding: 10px; background: #222; border: 1px solid #333; color: white; border-radius: 5px; }
    .gb-form-group input:focus, .gb-form-group textarea:focus { outline: none; border-color: #00ff88; }
    .gb-char-counter { display: block; text-align: right; font-size: 12px; color: #ccc; margin-top: 5px; }
    .gb-mod-page { max-width: 1000px; margin: 0 auto; padding: 30px; }
    .gb-mod-header { margin-bottom: 30px; }
    .gb-mod-header h1 { font-size: 36px; margin-bottom: 15px; }
    .gb-mod-badges { display: flex; gap: 10px; flex-wrap: wrap; }
    .gb-mod-meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; padding: 20px; background: #222; border-radius: 8px; }
    .gb-meta-item { display: flex; flex-direction: column; }
    .gb-meta-label { font-size: 12px; color: #ccc; margin-bottom: 5px; }
    .gb-meta-value { font-size: 16px; font-weight: bold; color: #00ff88; }
    .gb-mod-description { margin-bottom: 30px; }
    .gb-mod-description h2 { margin-bottom: 15px; }
    .gb-description-content { background: #222; padding: 20px; border-radius: 8px; line-height: 1.6; white-space: pre-wrap; }
    .gb-tag-list { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
    .gb-tag { background: #333; padding: 4px 12px; border-radius: 20px; font-size: 12px; color: #00ff88; }
    .gb-mod-actions { display: flex; gap: 15px; margin-top: 30px; }
    .gb-btn-large { padding: 15px 30px; font-size: 18px; }
    .gb-error-container { text-align: center; padding: 50px; }
    .gb-no-results { text-align: center; padding: 60px; color: #ccc; background: #1a1a1a; border-radius: 10px; }
    .gb-error { text-align: center; padding: 40px; color: #ff4444; background: #1a1a1a; border-radius: 8px; }
  `;
  document.head.appendChild(style);

  /* =========================
     SECURE HELPERS
  ========================= */
  function val(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }
  function fileEl(id) {
    const el = document.getElementById(id);
    return el?.files ? el.files[0] : null;
  }
  function escapeHTML(str) {
    if (!str) return "";
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
  function getQueryParam(name) {
    return new URLSearchParams(window.location.search).get(name);
  }
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  const rateLimiter = (() => {
    return (action, maxAttempts = 5, windowMs = 60000) => {
      const windowId = Math.floor(Date.now() / windowMs);
      const key = `gb_ratelimit_${action}_${windowId}`;
      let attempts = parseInt(localStorage.getItem(key) || '0');
      if (attempts >= maxAttempts) return false;
      localStorage.setItem(key, (attempts + 1).toString());
      setTimeout(() => localStorage.removeItem(key), windowMs);
      return true;
    };
  })();
  function setLoading(button, isLoading, text = 'Loading...') {
    if (!button) return;
    if (isLoading) {
      button.dataset.originalText = button.innerHTML;
      button.innerHTML = `<span class="gb-loading-spinner"></span> ${text}`;
      button.disabled = true;
      button.style.opacity = '0.7';
    } else {
      button.innerHTML = button.dataset.originalText || 'Submit';
      button.disabled = false;
      button.style.opacity = '1';
    }
  }

    // ===== BAD WORD FILTER =====
  const badWords = [
    'fuck', 'shit', 'ass', 'bitch', 'cunt', 'dick', 'pussy', 'whore', 'slut',
    'nigger', 'nigga', 'faggot', 'retard', 'bastard', 'piss', 'cock', 'balls',
    'asshole', 'motherfucker', 'damn', 'hell'
  ];

  function filterBadWords(text) {
    if (!text) return text;
    let filtered = text;
    badWords.forEach(word => {
      const regex = new RegExp('\\b' + word + '\\b', 'gi');
      filtered = filtered.replace(regex, '*'.repeat(word.length));
    });
    return filtered;
  }


  /* =========================
     AUTH STATE MANAGEMENT
  ========================= */
  async function checkAuthState() {
    try {
      const { data: { user }, error } = await supabaseClient.auth.getUser();
      if (error || !user) {
        currentUser = null;
        currentUserProfile = null;
        currentUserRole = null;
        isAuthenticated = false;
        showPublicUI();
        return;
      }
      let { data: profile } = await supabaseClient
        .from('profiles')
        .select('*')
        .eq('id', user.id)
        .single();
      if (!profile) {
        const { data: newProfile } = await supabaseClient
          .from('profiles')
          .insert({
            id: user.id,
            username: user.email.split('@')[0],
            email: user.email,
            role: 'user',
            trust_score: 100,
            is_verified: false,
            join_date: new Date().toISOString(),
            upload_count: 0,
            download_count: 0
          })
          .select()
          .single();
        profile = newProfile;
      }
      if (profile.banned) {
        showNotification('Your account has been banned.', 'error');
        await supabaseClient.auth.signOut();
        currentUser = null;
        currentUserProfile = null;
        currentUserRole = null;
        isAuthenticated = false;
        showPublicUI();
        return;
      }
      currentUser = user;
      currentUserProfile = profile;
      currentUserRole = profile.role || 'user';
      isAuthenticated = true;
      if (profile.is_shadow_banned) {
        showNotification('Account restricted', 'error');
        await logout();
        return;
      }
      showAuthenticatedUI(user, profile);
      startSessionCheck();
      resetInactivityTimer();
    } catch (err) {
      console.error('Auth check failed:', err);
      showPublicUI();
    }
  }
  function startSessionCheck() {
    if (sessionCheckInterval) clearInterval(sessionCheckInterval);
    sessionCheckInterval = setInterval(async () => {
      const { data: { session } } = await supabaseClient.auth.getSession();
      if (!session) {
        showNotification('Session expired. Please login again.', 'info');
        await logout();
      }
    }, 60000);
  }
  function showPublicUI() {
    const authSection = document.getElementById('auth-section');
    if (authSection) authSection.style.display = 'block';
    const userSection = document.getElementById('user-section');
    if (userSection) userSection.style.display = 'none';
    const nav = document.getElementById('main-nav');
    if (nav) {
      nav.innerHTML = `
        <div class="gb-nav-container">
          <a href="index.html" class="gb-nav-item active">🏠 Home</a>
          <span class="gb-nav-disabled" title="Login required">📤 Upload</span>
          <span class="gb-nav-disabled" title="Login required">👤 Profile</span>
          <span class="gb-nav-brand">Baldi Mods Hub</span>
        </div>
      `;
    }
  }
  function showAuthenticatedUI(user, profile) {
    const authSection = document.getElementById('auth-section');
    if (authSection) authSection.style.display = 'none';
    const userSection = document.getElementById('user-section');
    if (userSection) {
      userSection.style.display = 'block';
      const userEmailEl = document.getElementById('userEmail');
      if (userEmailEl) userEmailEl.textContent = user.email;
      const roleBadge = document.getElementById('userRole');
      if (roleBadge) {
        roleBadge.className = `gb-badge ${profile.role || 'user'}`;
        roleBadge.textContent = profile.role === 'admin' ? '👑 ADMIN' : 
                               profile.role === 'moderator' ? '🛡️ MOD' : 
                               profile.is_verified ? '✅ VERIFIED' : '👤 USER';
      }
    }
    const nav = document.getElementById('main-nav');
    if (nav) {
      let adminLinks = '';
      if (profile.role === 'admin' || profile.role === 'moderator') {
        adminLinks += `<a href="admin.html" class="gb-nav-item">🛡️ Moderation</a>`;
      }
      if (profile.role === 'admin') {
        adminLinks += `<a href="admin-dashboard.html" class="gb-nav-item">📊 Dashboard</a>`;
      }
      nav.innerHTML = `
        <div class="gb-nav-container">
          <a href="index.html" class="gb-nav-item">🏠 Home</a>
          <a href="upload.html" class="gb-nav-item">📤 Upload</a>
          <a href="profile.html" class="gb-nav-item">👤 ${profile.username || 'Profile'}</a>
          ${adminLinks}
          <span class="gb-nav-user">
            <span class="gb-badge ${profile.role || 'user'}">${profile.role?.toUpperCase() || 'USER'}</span>
            <span class="gb-nav-points">⭐ ${profile.trust_score || 0}</span>
          </span>
        </div>
      `;
    }
  }

  /* =========================
     AUTH FUNCTIONS
  ========================= */

  async function signUp() {
    const email = val("email");
    const password = val("password");
    if (!email || !password) return showNotification("Email and password required", "error");
    if (password.length < 8) return showNotification("Password must be at least 8 characters", "error");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return showNotification("Invalid email format", "error");
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    if (!(hasUpperCase && hasLowerCase && hasNumbers)) return showNotification("Password must contain uppercase, lowercase, and numbers", "error");
    const button = event?.target;
    setLoading(button, true, 'Creating account...');
    try {
      const { data, error } = await supabaseClient.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: window.location.origin,
          data: { username: email.split('@')[0], join_date: new Date().toISOString() }
        }
      });
      if (error) throw error;
      if (data.user) {
        await supabaseClient.from("profiles").upsert({
          id: data.user.id,
          username: email.split('@')[0],
          email: email,
          role: 'user',
          trust_score: 100,
          is_verified: false,
          join_date: new Date().toISOString(),
          upload_count: 0,
          download_count: 0
        }, { onConflict: 'id' });
        const { error: signInError } = await supabaseClient.auth.signInWithPassword({ email, password });
        if (signInError) throw signInError;
        showNotification("🎉 Account created successfully! Welcome to Baldi Mods Hub!", "success", 6000);
        setTimeout(() => {
          checkAuthState();
          window.location.href = "profile.html";
        }, 2000);
      }
    } catch (err) {
      console.error("Signup failed:", err);
      if (err.message.includes('User already registered')) {
        showNotification("Email already registered. Please login.", "error");
      } else {
        showNotification("Signup failed: " + (err.message || "Unknown error"), "error");
      }
    } finally {
      setLoading(button, false);
    }
  }

  async function signIn() {
    if (!rateLimiter('signin', 5, 60000)) return showNotification("Too many attempts. Please wait 1 minute.", "error");
    const email = val("email");
    const password = val("password");
    if (!email || !password) return showNotification("Email and password required", "error");
    const button = event?.target;
    setLoading(button, true, 'Logging in...');
    try {
      const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
      if (error) throw error;
      await supabaseClient
        .from("profiles")
        .update({ last_login: new Date().toISOString(), last_login_ip: null })
        .eq("id", data.user.id);
      showNotification("✅ Welcome back! Redirecting...", "success");
      await checkAuthState();
      setTimeout(() => window.location.href = "index.html", 1000);
    } catch (err) {
      console.error("Login failed:", err);
      if (err.message.includes('Invalid login credentials')) {
        showNotification("Invalid email or password", "error");
      } else {
        showNotification("Login failed: " + (err.message || "Unknown error"), "error");
      }
    } finally {
      setLoading(button, false);
    }
  }

  async function logout() {
    try {
      await supabaseClient.auth.signOut();
      currentUser = null;
      currentUserProfile = null;
      currentUserRole = null;
      isAuthenticated = false;
      if (sessionCheckInterval) {
        clearInterval(sessionCheckInterval);
        sessionCheckInterval = null;
      }
      if (inactivityTimer) {
        clearTimeout(inactivityTimer);
        inactivityTimer = null;
      }
      showNotification("👋 Logged out successfully", "success");
      showPublicUI();
      setTimeout(() => window.location.href = "index.html", 1000);
    } catch (err) {
      console.error("Logout failed:", err);
      showNotification("Logout failed", "error");
    }
  }

  async function getCurrentUser() { if (currentUser) return currentUser; try { const { data: { user } } = await supabaseClient.auth.getUser(); currentUser = user; return user; } catch { return null; } }
  async function getCurrentUserRole() { if (currentUserRole) return currentUserRole; const user = await getCurrentUser(); if (!user) return null; try { const { data } = await supabaseClient.from("profiles").select("role").eq("id", user.id).single(); currentUserRole = data?.role || 'user'; return currentUserRole; } catch { return 'user'; } }
  async function isAdmin() { const role = await getCurrentUserRole(); return role === 'admin'; }
  async function isModerator() { const role = await getCurrentUserRole(); return role === 'admin' || role === 'moderator'; }
  async function isAdmin() {
    const role = await getCurrentUserRole();
    return role === 'admin';
  }

  async function isModerator() {
    const role = await getCurrentUserRole();
    return role === 'admin' || role === 'moderator';
  }

  /* =========================
     PAGE GUARDS
  ========================= */

  async function guardUploadPage() { const user = await getCurrentUser(); if (!user) { showNotification("Please login to upload mods", "error"); setTimeout(() => window.location.href = "index.html", 1500); return false; } return true; }
  async function guardProfilePage() { const user = await getCurrentUser(); if (!user) { showNotification("Please login to view your profile", "error"); setTimeout(() => window.location.href = "index.html", 1500); return false; } return true; }
  async function guardAdminPage() { if (!await isModerator()) { showNotification("Moderator access required", "error"); setTimeout(() => window.location.href = "index.html", 1500); return false; } return true; }
  async function guardAdminDashboard() { if (!await isAdmin()) { showNotification("Admin access required", "error"); setTimeout(() => window.location.href = "index.html", 1500); return false; } return true; }

  /* =========================
     MOD UPLOAD – MEGA.NZ VERSION
  ========================= */

async function uploadMod() {
  const user = await getCurrentUser();
  if (!user) return showNotification("Please login to upload", "error");

  const title = val("title");
  const description = val("description");
  const version = val("version") || "1.0.0";
  const baldiVersion = val("baldiVersion");
  const tags = val("tags");
  const file = fileEl("file");
  const mainScreenshot = fileEl("mainScreenshot");
  const additionalScreenshots = document.getElementById('screenshots')?.files;

  // Validation
  if (!title || title.length < 3 || title.length > 100) 
    return showNotification("Title must be 3-100 characters", "error");
  if (!description || description.length < 10 || description.length > 5000) 
    return showNotification("Description must be 10-5000 characters", "error");
  if (!file) return showNotification("Please select a mod file", "error");
  if (!mainScreenshot) return showNotification("Please select a main screenshot", "error");

  const allowedExtensions = window.ENV?.ALLOWED_FILE_TYPES || ['.zip', '.rar', '.7z', '.baldimod'];
  const maxSize = window.ENV?.MAX_UPLOAD_SIZE || 100 * 1024 * 1024; // 100MB default

  const fileExt = '.' + file.name.split('.').pop().toLowerCase();
  if (!allowedExtensions.includes(fileExt)) 
    return showNotification(`Only ${allowedExtensions.join(', ')} files allowed`, "error");

  if (file.size > maxSize) 
    return showNotification(`File size exceeds ${Math.round(maxSize / (1024*1024))}MB limit`, "error");

  const button = document.querySelector('button[onclick="uploadMod()"]');
  setLoading(button, true, '📤 Uploading...');

  const progressDiv = document.createElement('div');
  progressDiv.className = 'gb-progress-card';
  progressDiv.innerHTML = '<div class="gb-progress-spinner"></div> Preparing upload...';
  document.querySelector('.gb-upload-form')?.appendChild(progressDiv);

  try {
    // ===== 1. Upload screenshots to Supabase Storage (for display) =====
    progressDiv.innerHTML = '<div class="gb-progress-spinner"></div> Uploading screenshots...';

    // Upload main screenshot to Supabase
    const mainExt = mainScreenshot.name.split('.').pop();
    const mainPath = `${user.id}/main_${Date.now()}.${mainExt}`;
    const { error: mainUploadError } = await supabaseClient.storage
      .from('mod-screenshots')
      .upload(mainPath, mainScreenshot);
    if (mainUploadError) throw mainUploadError;
    const { data: mainUrlData } = supabaseClient.storage
      .from('mod-screenshots')
      .getPublicUrl(mainPath);
    const mainScreenshotUrl = mainUrlData.publicUrl;

    // Upload additional screenshots to Supabase (max 2)
    const screenshotUrls = [];
    if (additionalScreenshots && additionalScreenshots.length > 0) {
      const maxAdditional = 2;
      for (let i = 0; i < Math.min(additionalScreenshots.length, maxAdditional); i++) {
        const file = additionalScreenshots[i];
        progressDiv.innerHTML = `<div class="gb-progress-spinner"></div> Uploading screenshot ${i+1}...`;
        const ext = file.name.split('.').pop();
        const path = `${user.id}/add_${Date.now()}_${i}.${ext}`;
        const { error: addUploadError } = await supabaseClient.storage
          .from('mod-screenshots')
          .upload(path, file);
        if (addUploadError) throw addUploadError;
        const { data: urlData } = supabaseClient.storage
          .from('mod-screenshots')
          .getPublicUrl(path);
        screenshotUrls.push(urlData.publicUrl);
      }
    }

    // ===== 2. Upload all files to Mega backend (to satisfy backend validation) =====
    progressDiv.innerHTML = '<div class="gb-progress-spinner"></div> Uploading mod file to Mega...';

    const formData = new FormData();
    formData.append('mainScreenshot', mainScreenshot);          // send original file
    // Send additional screenshots – convert FileList to array before forEach
    if (additionalScreenshots) {
      Array.from(additionalScreenshots).forEach(f => formData.append('screenshots', f));
    }
    formData.append('modFile', file);

    // Log what's being sent (for debugging)
    console.log('Sending to Mega backend:');
    for (let pair of formData.entries()) {
      console.log(pair[0], pair[1] instanceof File ? pair[1].name : pair[1]);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 300000); // 5 min

// Get Supabase session token
const { data: sessionData } = await supabaseClient.auth.getSession();

if (!sessionData.session) {
  throw new Error("Not logged in");
}

const accessToken = sessionData.session.access_token;

const response = await fetch(MEGA_BACKEND_URL, {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${accessToken}`
  },
  body: formData,
  signal: controller.signal
});




    if (!response.ok) {
      let errorText;
      try {
        const errorJson = await response.json();
        errorText = errorJson.error || errorJson.message || JSON.stringify(errorJson);
      } catch {
        errorText = await response.text();
      }
      throw new Error(`Server error ${response.status}: ${errorText || 'Unknown error'}`);
    }

    const result = await response.json();
    const { modFileUrl } = result; // we ignore screenshot URLs from Mega

    if (!modFileUrl) {
      throw new Error('Server response missing modFileUrl');
    }

    // ===== 3. Build screenshots array (using Supabase URLs) =====
    const screenshotsArray = [
      { url: mainScreenshotUrl, is_main: true, sort_order: 0 },
      ...screenshotUrls.map((url, i) => ({ url, is_main: false, sort_order: i + 1 }))
    ];

    const tagArray = tags ? tags.split(',').map(t => t.trim()).filter(t => t) : [];

    // ===== 4. Insert mod record into database =====
    progressDiv.innerHTML = '<div class="gb-progress-spinner"></div> Saving mod data...';
    const { error: dbError } = await supabaseClient
      .from("mods2")
      .insert([{
        title: title.trim(),
        description: description.trim(),
        version: version,
        baldi_version: baldiVersion,
        tags: tagArray,
        file_url: modFileUrl,
        file_storage_path: null,
        user_id: user.id,
        author_name: currentUserProfile?.username || user.email?.split('@')[0],
        approved: false,
        reported: false,
        quarantine: false,
        file_hash: null,
        file_size: file.size,
        file_extension: fileExt,
        original_filename: file.name,
        scan_status: 'pending',
        risk_score: 0,
        threat_cluster: null,
        scan_reason: null,
        screenshots: screenshotsArray,
        download_count: 0,
        view_count: 0,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }]);

    if (dbError) throw dbError;

    // Update user profile upload count
    await supabaseClient
      .from("profiles")
      .update({ upload_count: supabaseClient.rpc('increment', { x: 1 }) })
      .eq("id", user.id);

    progressDiv.remove();
    showNotification("✅ Mod uploaded! Pending review.", "success", 8000);

    // Clear form
    ['title', 'description', 'version', 'baldiVersion', 'tags', 'file', 'mainScreenshot', 'screenshots'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = id === 'version' ? '1.0.0' : '';
    });
    document.getElementById('screenshotPreviews').innerHTML = '';

    setTimeout(() => window.location.href = "profile.html", 2000);

  } catch (err) {
    console.error("Upload failed:", err);
    progressDiv.remove();
    if (err.name === 'AbortError') {
      showNotification("Upload timed out – please try again or check your connection.", "error");
    } else {
      showNotification("Upload failed: " + err.message, "error");
    }
  } finally {
    setLoading(button, false);
  }
}

  /* =========================
     MOD PAGE
  ========================= */

async function loadModPage() {
  const id = getQueryParam("id");
  if (!id) { window.location.href = "index.html"; return; }

  try {
    const { data: mod, error } = await supabaseClient
      .from("mods2")
      .select("*")
      .eq("id", id)
      .single();

    if (error || !mod) {
      console.error("Supabase error:", error);
      document.body.innerHTML = `<div class="gb-error-container"><h1>Mod not found</h1><p>${error?.message || 'Unknown error'}</p><a href="index.html" class="gb-btn gb-btn-primary">Back to Home</a></div>`;
      return;
    }

    const user = await getCurrentUser();

    // ===== VIEW COUNT LOGIC (unique per user / per browser) =====
    let shouldIncrement = false;

    if (user) {
      // Logged‑in user: check user_views table
      if (user.id !== mod.user_id) {
        const { data: existingView } = await supabaseClient
          .from('user_views')
          .select('id')
          .eq('user_id', user.id)
          .eq('mod_id', mod.id)
          .maybeSingle();

        if (!existingView) {
          shouldIncrement = true;
          // Record the view for next time
          await supabaseClient
            .from('user_views')
            .insert({ user_id: user.id, mod_id: mod.id })
            .catch(err => console.warn("Failed to record user view:", err));
        }
      }
    } else {
      // Anonymous user: use localStorage
      const storageKey = `viewed_mod_${mod.id}`;
      if (!localStorage.getItem(storageKey)) {
        shouldIncrement = true;
        localStorage.setItem(storageKey, 'true');
      }
    }

    if (shouldIncrement) {
      try {
        await supabaseClient.rpc('increment_view_count', { mod_id: mod.id });
      } catch (err) {
        console.warn("Failed to increment view count:", err);
      }
    }

    // Fetch author profile
    const { data: authorProfile } = await supabaseClient
      .from("profiles")
      .select("username, trust_score, upload_count, download_count, is_verified, role")
      .eq("id", mod.user_id)
      .single();

    if (authorProfile && authorProfile.download_count === undefined) {
      const { data: userMods } = await supabaseClient
        .from("mods2")
        .select("download_count")
        .eq("user_id", mod.user_id);
      const totalDownloads = userMods?.reduce((sum, m) => sum + (m.download_count || 0), 0) || 0;
      authorProfile.download_count = totalDownloads;
    }

    // Fetch buddy, subscriber, thank status for current user
    let isBuddy = false, isSubscribed = false, hasThanked = false;
    if (user) {
      const [buddyRes, subRes, thankRes] = await Promise.all([
        supabaseClient.from('buddies').select('id').eq('user_id', user.id).eq('buddy_id', mod.user_id).maybeSingle(),
        supabaseClient.from('subscriptions').select('id').eq('subscriber_id', user.id).eq('target_id', mod.user_id).maybeSingle(),
        supabaseClient.from('thanks').select('id').eq('mod_id', mod.id).eq('user_id', user.id).maybeSingle()
      ]);
      isBuddy = !!buddyRes.data;
      isSubscribed = !!subRes.data;
      hasThanked = !!thankRes.data;
    }

    const modContainer = document.getElementById("mod");
    if (!modContainer) return;

    // Generate screenshot gallery HTML
    let screenshotsHtml = '';
    if (mod.screenshots && mod.screenshots.length > 0) {
      const sorted = mod.screenshots.sort((a,b) => (a.sort_order||0) - (b.sort_order||0));
      screenshotsHtml = `
        <div class="gb-screenshots">
          <h2>Screenshots</h2>
          <div class="gb-screenshot-grid">
            ${sorted.map(s => `
              <div class="gb-screenshot-item ${s.is_main ? 'main' : ''}">
                <img src="${escapeHTML(s.url)}" alt="Screenshot" loading="lazy">
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // Determine author badge
    let authorBadge = '👤 MEMBER';
    if (authorProfile?.role === 'admin') authorBadge = '👑 ADMIN';
    else if (authorProfile?.role === 'moderator') authorBadge = '🛡️ MOD';
    else if (authorProfile?.is_verified) authorBadge = '✅ VERIFIED';

    // Check if current user is author or moderator
    const isAuthor = user && user.id === mod.user_id;
    const canEdit = isAuthor || (user && await isModerator());

    modContainer.innerHTML = `
      <div class="gb-mod-grid">
        <!-- Sidebar (Author Info) -->
        <div class="gb-mod-sidebar">
          <div class="gb-author-cover"></div>
          <div class="gb-author-avatar" style="text-shadow: 0 0 8px var(--gb-primary);">
            ${escapeHTML((authorProfile?.username || 'U').charAt(0).toUpperCase())}
          </div>
          <div class="gb-author-info">
            <div class="gb-author-name"><a href="profile.html?id=${mod.user_id}" style="color: inherit; text-decoration: none;">${escapeHTML(authorProfile?.username || 'Unknown')}</a></div>
            <div class="gb-author-badge">${authorBadge}</div>
            
            <div class="gb-author-stats">
              <div class="gb-author-stat">
                <span>📦 Uploads</span>
                <span class="gb-author-stat-value">${authorProfile?.upload_count || 0}</span>
              </div>
              <div class="gb-author-stat">
                <span>📥 Downloads</span>
                <span class="gb-author-stat-value">${authorProfile?.download_count || 0}</span>
              </div>
              <div class="gb-author-stat">
                <span>⭐ Trust</span>
                <span class="gb-author-stat-value">${authorProfile?.trust_score || 0}</span>
              </div>
            </div>

            <div class="gb-author-actions">
              <button onclick="toggleBuddy('${mod.user_id}')" class="gb-btn ${isBuddy ? 'gb-btn-primary' : 'gb-btn-outline'} gb-btn-block" id="buddyBtn-${mod.user_id}">${isBuddy ? '✓ Buddy' : '+ Add Buddy'}</button>
              <button onclick="toggleSubscribe('${mod.user_id}')" class="gb-btn ${isSubscribed ? 'gb-btn-primary' : 'gb-btn-outline'} gb-btn-block" id="subBtn-${mod.user_id}">${isSubscribed ? '🔔 Subscribed' : '🔔 Subscribe'}</button>
              <button onclick="toggleThank('${mod.id}')" class="gb-btn ${hasThanked ? 'gb-btn-primary' : 'gb-btn-outline'} gb-btn-block" id="thankBtn-${mod.id}">${hasThanked ? '❤️ Thanked' : '❤️ Thank'}</button>
            </div>
          </div>
        </div>

        <!-- Main Content -->
        <div class="gb-mod-main">
          <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px; flex-wrap: wrap;">
            <h1 class="gb-mod-title" style="margin: 0;">${escapeHTML(mod.title)}</h1>
            ${canEdit ? `<a href="editmod.html?id=${mod.id}" class="gb-btn gb-btn-secondary" style="padding: 8px 16px;">✎ Edit</a>` : ''}
          </div>
          
          <div class="gb-mod-badges">
            <span class="gb-badge">📦 v${escapeHTML(mod.version || '1.0.0')}</span>
            <span class="gb-badge">🎮 ${escapeHTML(mod.baldi_version || 'Any')}</span>
            <span class="gb-badge" style="background:${mod.risk_score < 30 ? '#00ff88' : mod.risk_score < 60 ? '#ffaa00' : '#ff4444'};">
              ${mod.risk_score < 30 ? '✅ Safe' : mod.risk_score < 60 ? '⚠️ Caution' : '❌ Unsafe'}
            </span>
          </div>

          <div class="gb-mod-meta-grid">
            <div class="gb-meta-item"><span class="gb-meta-label">Downloads</span><span class="gb-meta-value">📥 ${mod.download_count || 0}</span></div>
            <div class="gb-meta-item"><span class="gb-meta-label">Views</span><span class="gb-meta-value">👁️ ${mod.view_count || 0}</span></div>
            <div class="gb-meta-item"><span class="gb-meta-label">Uploaded</span><span class="gb-meta-value">📅 ${new Date(mod.created_at).toLocaleDateString()}</span></div>
            <div class="gb-meta-item"><span class="gb-meta-label">File Size</span><span class="gb-meta-value">💾 ${formatFileSize(mod.file_size || 0)}</span></div>
          </div>

          ${screenshotsHtml}

          <div class="gb-mod-description">
            <h2>Description</h2>
            <div class="gb-description-content">${escapeHTML(mod.description).replace(/\n/g, '<br>')}</div>
          </div>

          ${mod.tags?.length ? `
            <div class="gb-tag-list">
              ${mod.tags.map(tag => `<span class="gb-tag">#${escapeHTML(tag)}</span>`).join('')}
            </div>
          ` : ''}

          <!-- Favorite Button -->
          <div class="gb-mod-favorite">
            <button id="favoriteBtn" onclick="toggleFavorite('${mod.id}')" class="gb-btn gb-btn-outline gb-btn-large">🤍 Favorite</button>
          </div>

          <div class="gb-mod-actions">
            <a href="${escapeHTML(mod.file_url)}" class="gb-btn gb-btn-primary gb-btn-large" target="_blank" rel="noopener noreferrer" onclick="trackDownload('${mod.id}')">⬇️ Download Mod</a>
            <button onclick="reportMod('${mod.id}')" class="gb-btn gb-btn-secondary gb-btn-large">🚩 Report Mod</button>
          </div>

          <!-- Comments Section -->
          <div class="gb-comments-section">
            <h2>Comments</h2>
            ${user ? `
              <div class="gb-add-comment">
                <textarea id="commentInput" placeholder="Write a comment..." rows="3"></textarea>
                <button onclick="addComment('${mod.id}', document.getElementById('commentInput').value)" class="gb-btn gb-btn-primary">Post Comment</button>
              </div>
            ` : '<p><a href="index.html">Login</a> to comment.</p>'}
            <div id="commentsContainer" class="gb-comments-container"></div>
          </div>
        </div>
      </div>
    `;

    // Load comments and favorite status after rendering
    loadComments(mod.id);
    updateFavoriteButton(mod.id);

  } catch (err) {
    console.error("Failed to load mod:", err);
    document.body.innerHTML = `<div class="gb-error-container"><h1>Error loading mod</h1><p>${err.message}</p><a href="index.html" class="gb-btn gb-btn-primary">Back to Home</a></div>`;
  }
}
  /* =========================
     MOD LISTING
  ========================= */

  async function loadMods() {
    const box = document.getElementById("mods");
    if (!box) return;

    try {
      let query = supabaseClient
        .from("mods2")
        .select(`
          id,
          title,
          description,
          file_url,
          user_id,
          author_name,
          download_count,
          view_count,
          created_at,
          version,
          risk_score,
          tags,
          baldi_version,
          file_size
        `)
        .eq("approved", true)
        .eq("quarantine", false)
        .order("created_at", { ascending: false })
        .limit(50);

      const search = document.getElementById("search")?.value;
      if (search?.length >= 2) {
        query = query.ilike("title", `%${search}%`);
      }

      const { data, error } = await query;
      if (error) throw error;

      if (!data?.length) {
        box.innerHTML = '<div class="gb-no-results">📭 No mods found</div>';
        return;
      }

      const userIds = [...new Set(data.map(m => m.user_id))];
      const { data: profiles } = await supabaseClient
        .from("profiles")
        .select("id, username, is_shadow_banned")
        .in("id", userIds);

      const profileMap = {};
      profiles?.forEach(p => { if (!p.is_shadow_banned) profileMap[p.id] = p.username; });

      box.innerHTML = data.map(mod => {
        if (!profileMap[mod.user_id]) return '';
        const modId = escapeHTML(mod.id);
        const title = escapeHTML(mod.title);
        const description = escapeHTML(mod.description.substring(0, 120) + (mod.description.length > 120 ? '...' : ''));
        const author = escapeHTML(profileMap[mod.user_id] || 'Unknown');
        const version = escapeHTML(mod.version || '1.0.0');
        const fileSize = mod.file_size ? formatFileSize(mod.file_size) : 'Unknown';
        const date = new Date(mod.created_at).toLocaleDateString();
        let riskBadge = '';
        if (mod.risk_score > 70) riskBadge = '<span class="gb-badge" style="background:#ff4444;">⚠️ High Risk</span>';
        else if (mod.risk_score > 40) riskBadge = '<span class="gb-badge" style="background:#ffaa00;">⚠️ Medium Risk</span>';
        let baldiBadge = '';
        if (mod.baldi_version) baldiBadge = `<span class="gb-badge">🎮 ${escapeHTML(mod.baldi_version)}</span>`;
        return `
          <div class="gb-card mod-card" style="display: flex; flex-direction: column; height: 100%;" data-mod-id="${modId}">
            <div style="flex: 1;">
              <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                <h3 style="margin: 0;"><a href="mod.html?id=${encodeURIComponent(modId)}" style="color: #00ff88; text-decoration: none;">${title}</a></h3>
                <div>${riskBadge}</div>
              </div>
              <div style="display: flex; gap: 10px; margin-bottom: 15px; font-size: 12px; color: #ccc; flex-wrap: wrap;">
                <span style="background: #333; padding: 4px 8px; border-radius: 4px;">📦 v${version}</span>
                <span style="background: #333; padding: 4px 8px; border-radius: 4px;">👤 ${author}</span>
                ${baldiBadge}
                <span style="background: #333; padding: 4px 8px; border-radius: 4px;">📅 ${date}</span>
              </div>
              <p style="color: #ccc; line-height: 1.6; margin-bottom: 15px;">${description}</p>
              <div style="display: flex; gap: 8px; margin-bottom: 15px; flex-wrap: wrap;">
                ${mod.tags?.slice(0, 3).map(tag => `<span style="background: #333; padding: 4px 12px; border-radius: 20px; font-size: 12px; color: #00ff88;">#${escapeHTML(tag)}</span>`).join('') || ''}
              </div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 15px; border-top: 1px solid var(--gb-border); padding-top: 15px;">
              <div style="display: flex; gap: 15px;">
                <span style="color: #00ff88; font-weight: bold;">📥 ${mod.download_count || 0}</span>
                <span style="color: #00ff88; font-weight: bold;">👁️ ${mod.view_count || 0}</span>
                <span style="color: #00ff88; font-weight: bold;">💾 ${fileSize}</span>
              </div>
              <div style="display: flex; gap: 10px;">
                <a href="${escapeHTML(mod.file_url)}" class="gb-btn gb-btn-primary" target="_blank" rel="noopener noreferrer" onclick="trackDownload('${modId}')">Download</a>
                <button onclick="reportMod('${modId}')" class="gb-btn gb-btn-secondary">Report</button>
              </div>
            </div>
          </div>
        `;
      }).join("");

    } catch (err) {
      console.error("Failed to load mods:", err);
      box.innerHTML = '<div class="gb-error">❌ Failed to load mods. Please refresh.</div>';
    }
  }

  let searchTimeout;
window.debouncedSearch = function() {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    loadMods();
  }, 300); // wait 300ms after user stops typing
};

  /* =========================
     TRACK DOWNLOAD
  ========================= */

 async function trackDownload(modId) {
  const user = await getCurrentUser();
  const { data: mod } = await supabaseClient.from("mods2").select("user_id").eq("id", modId).single();
  
  // Prevent author self-counting
  if (user && mod && user.id === mod.user_id) {
    showNotification("You cannot increase count while downloading your own mod", "info");
    return;
  }

  // For logged-out users, just allow download
  if (!user) {
    showNotification("Download started", "success");
    return;
  }

  // Check if user already downloaded this mod (optional)
  const { data: existingDownload } = await supabaseClient
    .from('user_downloads')
    .select('id')
    .eq('user_id', user.id)
    .eq('mod_id', modId)
    .maybeSingle();

  if (existingDownload) {
    showNotification("You have already downloaded this mod", "info");
    return;
  }

  try {
    // Increment mod download count (using your existing RPC)
    await supabaseClient.rpc('increment_download_count', { mod_id: modId });

    // Record this download in user_downloads (prevents duplicate counting)
    await supabaseClient
      .from('user_downloads')
      .insert({ user_id: user.id, mod_id: modId });

    // 👇 NEW: Increment author's total download count in profiles table
    // First get current count
    const { data: authorProfile } = await supabaseClient
      .from("profiles")
      .select("download_count")
      .eq("id", mod.user_id)
      .single();

    const newCount = (authorProfile?.download_count || 0) + 1;
    await supabaseClient
      .from("profiles")
      .update({ download_count: newCount })
      .eq("id", mod.user_id);

    showNotification("Download started", "success");
  } catch (err) {
    console.error("Failed to track download:", err);
    showNotification("Download count could not be updated", "error");
  }
}
  /* =========================
     BUDDY, SUBSCRIBE, THANK FUNCTIONS
  ========================= */

  async function toggleBuddy(targetUserId) {
    const user = await getCurrentUser();
    if (!user) { showNotification("Please login", "error"); return; }
    if (user.id === targetUserId) { showNotification("You cannot add yourself as a buddy", "warning"); return; }
    try {
      const { data: existing } = await supabaseClient
        .from('buddies')
        .select('id')
        .eq('user_id', user.id)
        .eq('buddy_id', targetUserId)
        .maybeSingle();
      if (existing) {
        const { error } = await supabaseClient.from('buddies').delete().eq('id', existing.id);
        if (error) throw error;
        showNotification("Buddy removed", "success");
      } else {
        const { error } = await supabaseClient.from('buddies').insert({ user_id: user.id, buddy_id: targetUserId });
        if (error) throw error;
        showNotification("Buddy added", "success");
      }
      const btn = document.getElementById(`buddyBtn-${targetUserId}`);
      if (btn) {
        const isNow = !existing;
        btn.innerHTML = isNow ? '✓ Buddy' : '+ Add Buddy';
        btn.className = isNow ? 'gb-btn gb-btn-primary gb-btn-block' : 'gb-btn gb-btn-outline gb-btn-block';
      }
    } catch (err) {
      console.error("Buddy error:", err);
      showNotification("Failed to update buddy", "error");
    }
  }

  async function toggleSubscribe(targetUserId) {
    const user = await getCurrentUser();
    if (!user) { showNotification("Please login", "error"); return; }
    if (user.id === targetUserId) { showNotification("You cannot subscribe to yourself", "warning"); return; }
    try {
      const { data: existing } = await supabaseClient
        .from('subscriptions')
        .select('id')
        .eq('subscriber_id', user.id)
        .eq('target_id', targetUserId)
        .maybeSingle();
      if (existing) {
        const { error } = await supabaseClient.from('subscriptions').delete().eq('id', existing.id);
        if (error) throw error;
        showNotification("Unsubscribed", "success");
      } else {
        const { error } = await supabaseClient.from('subscriptions').insert({ subscriber_id: user.id, target_id: targetUserId });
        if (error) throw error;
        showNotification("Subscribed", "success");
      }
      const btn = document.getElementById(`subBtn-${targetUserId}`);
      if (btn) {
        const isNow = !existing;
        btn.innerHTML = isNow ? '🔔 Subscribed' : '🔔 Subscribe';
        btn.className = isNow ? 'gb-btn gb-btn-primary gb-btn-block' : 'gb-btn gb-btn-outline gb-btn-block';
      }
    } catch (err) {
      console.error("Subscribe error:", err);
      showNotification("Failed to update subscription", "error");
    }
  }

  async function toggleThank(modId) {
    const user = await getCurrentUser();
    if (!user) { showNotification("Please login", "error"); return; }
    const { data: mod } = await supabaseClient.from('mods2').select('user_id').eq('id', modId).single();
    if (user.id === mod.user_id) { showNotification("You cannot thank your own mod", "warning"); return; }
    try {
      const { data: existing } = await supabaseClient
        .from('thanks')
        .select('id')
        .eq('mod_id', modId)
        .eq('user_id', user.id)
        .maybeSingle();
      if (existing) {
        const { error } = await supabaseClient.from('thanks').delete().eq('id', existing.id);
        if (error) throw error;
        showNotification("Thank removed", "success");
      } else {
        const { error } = await supabaseClient.from('thanks').insert({ mod_id: modId, user_id: user.id });
        if (error) throw error;
        showNotification("Thanked!", "success");
      }
      const btn = document.getElementById(`thankBtn-${modId}`);
      if (btn) {
        const isNow = !existing;
        btn.innerHTML = isNow ? '❤️ Thanked' : '❤️ Thank';
        btn.className = isNow ? 'gb-btn gb-btn-primary gb-btn-block' : 'gb-btn gb-btn-outline gb-btn-block';
      }
    } catch (err) {
      console.error("Thank error:", err);
      showNotification("Failed to update thank", "error");
    }
  }

  /* =========================
     PROFILE FUNCTIONS (own profile)
  ========================= */

  async function loadProfilePage() {
    const user = await getCurrentUser();
    if (!user) return;
    try {
      const { data: profile, error } = await supabaseClient
        .from('profiles')
        .select('*')
        .eq('id', user.id)
        .single();
      if (error && error.code === 'PGRST116') {
        const { data: newProfile } = await supabaseClient
          .from('profiles')
          .insert({
            id: user.id,
            username: user.email.split('@')[0],
            email: user.email,
            role: 'user',
            trust_score: 100,
            is_verified: false,
            join_date: new Date().toISOString(),
            upload_count: 0,
            download_count: 0
          })
          .select()
          .single();
        renderProfile(newProfile, user);
      } else if (!error) {
        renderProfile(profile, user);
      }
    } catch (err) {
      console.error('Failed to load profile:', err);
      showNotification('Failed to load profile', 'error');
    }
  }

   function renderProfile(profile, user) {
    const container = document.getElementById('profile-content');
    if (!container) return;
    const username = profile?.username || user.email?.split('@')[0] || 'User';
    const joinDate = profile?.join_date ? new Date(profile.join_date).toLocaleDateString() : 'Today';
    const trustScore = profile?.trust_score || 100;
    let trustColor = '#ff4444';
    if (trustScore >= 80) trustColor = '#00ff88';
    else if (trustScore >= 50) trustColor = '#ffaa00';
    container.innerHTML = `
      <div class="gb-profile-container">
        <div class="gb-profile-sidebar">
          <div class="gb-profile-avatar">
            <div class="gb-avatar">${username.charAt(0).toUpperCase()}</div>
            ${profile?.is_verified ? '<span class="gb-badge verified">✅ VERIFIED</span>' : ''}
          </div>
          <h2 style="text-align: center; margin: 10px 0 5px; color: #00ff88;">${escapeHTML(username)}</h2>
          <div style="text-align: center; color: #ccc; margin-bottom: 20px;">
            <span class="gb-badge ${profile?.role || 'user'}">${profile?.role?.toUpperCase() || 'USER'}</span>
          </div>
          <div class="gb-stats-grid">
            <div class="gb-stat"><span class="gb-stat-value">${profile?.upload_count || 0}</span><span class="gb-stat-label">Uploads</span></div>
            <div class="gb-stat"><span class="gb-stat-value">${profile?.download_count || 0}</span><span class="gb-stat-label">Downloads</span></div>
            <div class="gb-stat"><span class="gb-stat-value">${joinDate}</span><span class="gb-stat-label">Joined</span></div>
          </div>
          <div class="gb-trust-score">
            <div class="gb-trust-label"><span>Trust Score</span><span>${trustScore}</span></div>
            <div class="gb-trust-bar"><div class="gb-trust-fill" style="width:${trustScore}%; background:${trustColor};"></div></div>
          </div>
          <div class="gb-profile-bio">
            <h3>About</h3>
            <p>${escapeHTML(profile?.bio || 'No bio yet.')}</p>
          </div>
        </div>
        <div class="gb-profile-main">
          <div class="gb-tabs">
            <button class="gb-tab active" onclick="window.switchTab('uploads')">📦 My Mods</button>
            <button class="gb-tab" onclick="window.switchTab('stats')">📊 Statistics</button>
            <button class="gb-tab" onclick="window.switchTab('buddies')">👥 Buddies</button>
            <button class="gb-tab" onclick="window.switchTab('subscribers')">👤 Subscribers</button>
            <button class="gb-tab" onclick="window.switchTab('settings')">⚙️ Settings</button>
          </div>
          <div id="uploads-tab" class="gb-tab-content active">
            <h3>My Uploaded Mods</h3>
            <div id="myMods" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;"></div>
          </div>
          <div id="stats-tab" class="gb-tab-content">
            <h3>Statistics</h3>
            <div class="gb-stats-detailed">
              <div class="gb-stat-card"><div class="gb-stat-icon">📤</div><div class="gb-stat-info"><span class="gb-stat-label">Total Uploads</span><span class="gb-stat-number" id="statTotalUploads">0</span></div></div>
              <div class="gb-stat-card"><div class="gb-stat-icon">✅</div><div class="gb-stat-info"><span class="gb-stat-label">Approved</span><span class="gb-stat-number" id="statApprovedMods">0</span></div></div>
              <div class="gb-stat-card"><div class="gb-stat-icon">⏳</div><div class="gb-stat-info"><span class="gb-stat-label">Pending</span><span class="gb-stat-number" id="statPendingMods">0</span></div></div>
              <div class="gb-stat-card"><div class="gb-stat-icon">📥</div><div class="gb-stat-info"><span class="gb-stat-label">Downloads</span><span class="gb-stat-number" id="statTotalDownloads">0</span></div></div>
            </div>
          </div>
          <div id="buddies-tab" class="gb-tab-content">
            <h3>Buddies</h3>
            <div id="profileBuddiesList" class="gb-user-grid" style="grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 15px;"></div>
          </div>
          <div id="subscribers-tab" class="gb-tab-content">
            <h3>Subscribers</h3>
            <div id="profileSubscribersList" class="gb-user-grid" style="grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 15px;"></div>
          </div>
          <div id="settings-tab" class="gb-tab-content">
            <h3>Profile Settings</h3>
            <form class="gb-settings-form">
              <div class="gb-form-group">
                <label>Display Name</label>
                <input type="text" id="displayName" value="${escapeHTML(username)}" maxlength="30">
                <span class="gb-char-counter" id="nameCounter">${username.length}/30</span>
              </div>
              <div class="gb-form-group">
                <label>Bio</label>
                <textarea id="userBio" rows="4" maxlength="500" placeholder="Tell us about yourself...">${escapeHTML(profile?.bio || '')}</textarea>
                <span class="gb-char-counter" id="bioCounter">${profile?.bio?.length || 0}/500</span>
              </div>
              <div class="gb-form-group">
                <label>Email</label>
                <input type="email" value="${escapeHTML(user.email)}" disabled style="background: #333; opacity: 0.7;">
              </div>
              <button type="button" onclick="updateProfile()" class="gb-btn gb-btn-primary">💾 Save Changes</button>
            </form>
          </div>
        </div>
      </div>
    `;
    loadUserStats();
    loadMyMods();
  }

  async function loadMyMods() {
    const box = document.getElementById("myMods");
    if (!box) return;
    const user = await getCurrentUser();
    if (!user) return;
    try {
      const { data, error } = await supabaseClient
        .from("mods2")
        .select("*")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });
      if (error) throw error;
      if (!data?.length) {
        box.innerHTML = '<div class="gb-no-results">📭 You haven\'t uploaded any mods yet</div>';
        return;
      }
      box.innerHTML = data.map(mod => {
        let status = '', statusClass = '';
        if (mod.quarantine) { status = '⚠️ Quarantined'; statusClass = 'background: #ff4444; color: white;'; }
        else if (mod.approved) { status = '✅ Approved'; statusClass = 'background: #00ff88; color: black;'; }
        else { status = '⏳ Pending Review'; statusClass = 'background: #ffaa00; color: black;'; }
        return `
          <div class="gb-card" style="padding: 20px;">
            <h4 style="margin: 0 0 10px 0; color: #fff;">${escapeHTML(mod.title)}</h4>
            <div style="display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; margin: 10px 0; ${statusClass}">${status}</div>
            <div style="margin: 10px 0; color: #ccc; font-size: 12px;">
              <span>📦 v${escapeHTML(mod.version || '1.0.0')}</span>
              <span style="margin-left: 15px;">📥 ${mod.download_count || 0} downloads</span>
              <span style="margin-left: 15px;">📅 ${new Date(mod.created_at).toLocaleDateString()}</span>
            </div>
            ${mod.scan_reason ? `<p style="color: #ffaa00; font-size: 12px;">ℹ️ ${escapeHTML(mod.scan_reason)}</p>` : ''}
            <div style="display: flex; gap: 10px; margin-top: 15px;">
              <a href="${escapeHTML(mod.file_url)}" target="_blank" class="gb-btn gb-btn-primary" style="padding: 8px 16px; font-size: 14px;">📥 Download</a>
              ${!mod.approved && !mod.quarantine ? `<button onclick="deleteMod('${mod.id}')" class="gb-btn gb-btn-danger" style="padding: 8px 16px; font-size: 14px;">🗑️ Delete</button>` : ''}
            </div>
          </div>
        `;
      }).join("");
    } catch (err) {
      console.error("Failed to load my mods:", err);
      box.innerHTML = '<div class="gb-error">❌ Failed to load your mods</div>';
    }
  }

  async function loadUserStats() {
    const user = await getCurrentUser();
    if (!user) return;
    try {
      const { data: mods } = await supabaseClient
        .from('mods2')
        .select('*')
        .eq('user_id', user.id);
      const totalUploads = mods?.length || 0;
      const approvedMods = mods?.filter(m => m.approved).length || 0;
      const pendingMods = mods?.filter(m => !m.approved && !m.quarantine).length || 0;
      const totalDownloads = mods?.reduce((sum, m) => sum + (m.download_count || 0), 0) || 0;
      ['statTotalUploads', 'statApprovedMods', 'statPendingMods', 'statTotalDownloads'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = id === 'statTotalUploads' ? totalUploads :
                                id === 'statApprovedMods' ? approvedMods :
                                id === 'statPendingMods' ? pendingMods : totalDownloads;
      });
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  }

  async function updateProfile() {
    const user = await getCurrentUser();
    if (!user) return showNotification('Please login', 'error');
    const displayName = document.getElementById('displayName')?.value.trim();
    const bio = document.getElementById('userBio')?.value.trim();
    if (!displayName || displayName.length < 3) return showNotification('Display name must be at least 3 characters', 'error');
    const button = document.querySelector('.gb-btn-primary');
    setLoading(button, true, 'Saving...');
    try {
      const { error } = await supabaseClient
        .from('profiles')
        .update({
          username: displayName,
          bio: bio,
          updated_at: new Date().toISOString()
        })
        .eq('id', user.id);
      if (error) throw error;
      showNotification('✅ Profile updated successfully!', 'success');
      const usernameEl = document.querySelector('.gb-profile-sidebar h2');
      if (usernameEl) usernameEl.textContent = displayName;
      const avatarEl = document.querySelector('.gb-avatar');
      if (avatarEl) avatarEl.textContent = displayName.charAt(0).toUpperCase();
    } catch (err) {
      console.error('Failed to update profile:', err);
      showNotification('Failed to update profile', 'error');
    } finally {
      setLoading(button, false);
    }
  }

  window.switchTab = function(tabName) {
    document.querySelectorAll('.gb-tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.gb-tab').forEach(btn => btn.classList.remove('active'));
    const tabEl = document.getElementById(`${tabName}-tab`);
    if (tabEl) tabEl.classList.add('active');
    if (event.target) event.target.classList.add('active');
    if (tabName === 'stats') {
      loadUserStats();
    } else if (tabName === 'buddies' && currentUser) {
      loadProfileBuddies(currentUser.id);
    } else if (tabName === 'subscribers' && currentUser) {
      loadProfileSubscribers(currentUser.id);
    }
  };


  /* =========================
     ADMIN FUNCTIONS (unchanged)
  ========================= */

  async function loadAdminStats() {
    const box = document.getElementById("stats");
    if (!box || !await isAdmin()) return;
    try {
      const [
        { count: totalMods },
        { count: pendingMods },
        { count: reportedMods },
        { count: quarantinedMods },
        { count: totalUsers },
        { count: verifiedUsers },
        { data: mods }
      ] = await Promise.all([
        supabaseClient.from("mods2").select("*", { count: 'exact', head: true }),
        supabaseClient.from("mods2").select("*", { count: 'exact', head: true }).eq("approved", false).eq("quarantine", false),
        supabaseClient.from("mods2").select("*", { count: 'exact', head: true }).eq("reported", true),
        supabaseClient.from("mods2").select("*", { count: 'exact', head: true }).eq("quarantine", true),
        supabaseClient.from("profiles").select("*", { count: 'exact', head: true }),
        supabaseClient.from("profiles").select("*", { count: 'exact', head: true }).eq("is_verified", true),
        supabaseClient.from("mods2").select("download_count")
      ]);
      const totalDownloads = mods?.reduce((sum, m) => sum + (m.download_count || 0), 0) || 0;
      box.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px;">
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #00ff88;"><div style="font-size: 32px; margin-bottom: 10px;">📦</div><div style="font-size: 14px; color: #ccc;">Total Mods</div><div style="font-size: 36px; font-weight: bold; color: #00ff88;">${totalMods || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #ffaa00;"><div style="font-size: 32px; margin-bottom: 10px;">⏳</div><div style="font-size: 14px; color: #ccc;">Pending</div><div style="font-size: 36px; font-weight: bold; color: #ffaa00;">${pendingMods || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #ff4444;"><div style="font-size: 32px; margin-bottom: 10px;">🚩</div><div style="font-size: 14px; color: #ccc;">Reported</div><div style="font-size: 36px; font-weight: bold; color: #ff4444;">${reportedMods || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #ffaa00;"><div style="font-size: 32px; margin-bottom: 10px;">☣️</div><div style="font-size: 14px; color: #ccc;">Quarantined</div><div style="font-size: 36px; font-weight: bold; color: #ffaa00;">${quarantinedMods || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #2196f3;"><div style="font-size: 32px; margin-bottom: 10px;">👥</div><div style="font-size: 14px; color: #ccc;">Total Users</div><div style="font-size: 36px; font-weight: bold; color: #2196f3;">${totalUsers || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #00ff88;"><div style="font-size: 32px; margin-bottom: 10px;">✅</div><div style="font-size: 14px; color: #ccc;">Verified</div><div style="font-size: 36px; font-weight: bold; color: #00ff88;">${verifiedUsers || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #00ff88;"><div style="font-size: 32px; margin-bottom: 10px;">📥</div><div style="font-size: 14px; color: #ccc;">Downloads</div><div style="font-size: 36px; font-weight: bold; color: #00ff88;">${totalDownloads || 0}</div></div>
          <div style="background: #1a1a1a; padding: 25px; border-radius: 10px; border-left: 4px solid #00ff88;"><div style="font-size: 32px; margin-bottom: 10px;">💾</div><div style="font-size: 14px; color: #ccc;">Storage</div><div style="font-size: 36px; font-weight: bold; color: #00ff88;">${formatFileSize(window.ENV?.MAX_UPLOAD_SIZE || 2147483648)} Limit</div></div>
        </div>
      `;
    } catch (err) {
      console.error("Failed to load stats:", err);
      box.innerHTML = '<div class="gb-error">Failed to load stats</div>';
    }
  }

  // =========================
  // MODERATION ACTIONS (new)
  // =========================

  async function warnUser(userId, reason, note = '') {
    if (!await isModerator()) return;
    const mod = await getCurrentUser();
    if (!mod) return;
    try {
      const { error } = await supabaseClient
        .from('user_warnings')
        .insert({
          user_id: userId,
          moderator_id: mod.id,
          reason: reason,
          note: note
        });
      if (error) throw error;
      showNotification('User warned', 'success');
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error('Failed to warn user:', err);
      showNotification('Failed to warn user', 'error');
    }
  }

  async function unmuteUser(userId) {
    if (!await isModerator()) return;
    try {
      const { error } = await supabaseClient
        .from('profiles')
        .update({ muted_until: null })
        .eq('id', userId);
      if (error) throw error;
      showNotification('User unmuted', 'success');
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error('Failed to unmute user:', err);
      showNotification('Failed to unmute user', 'error');
    }
  }

  async function unbanUser(userId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient
        .from('profiles')
        .update({ is_shadow_banned: false, trust_score: 50 })
        .eq('id', userId);
      if (error) throw error;
      showNotification('User unbanned', 'success');
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error('Failed to unban user:', err);
      showNotification('Failed to unban user', 'error');
    }
  }

  async function loadUserWarnings(userId) {
    const { data, error } = await supabaseClient
      .from('user_warnings')
      .select(`
        *,
        profiles:moderator_id (username)
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false });
    if (error) {
      console.error('Failed to load warnings:', error);
      return [];
    }
    return data || [];
  }

  window.loadRiskUsers = async function() {
    const box = document.getElementById('riskyUsers');
    if (!box || !await isAdmin()) return;
    try {
      const now = new Date().toISOString();
      const { data, error } = await supabaseClient
        .from('profiles')
        .select(`
          id, username, email, trust_score, spam_flags, 
          is_shadow_banned, is_verified, upload_count, download_count, 
          join_date, muted_until, banned
        `)
        .or(`trust_score.lt.50,spam_flags.gt.5,is_shadow_banned.eq.true,muted_until.gt.${now},banned.eq.true`)
        .order('trust_score', { ascending: true })
        .limit(20);
      if (error) throw error;
      if (!data?.length) { box.innerHTML = '<div class="gb-no-results">No risky or muted users</div>'; return; }
      const usersWithWarnings = await Promise.all(data.map(async (user) => {
        const warnings = await loadUserWarnings(user.id);
        return { ...user, warnings };
      }));
      box.innerHTML = usersWithWarnings.map(user => {
        const isMuted = user.muted_until && new Date(user.muted_until) > new Date();
        const muteInfo = isMuted ? `<div style="margin-bottom: 5px;"><span style="background:#ffaa00; padding:2px 8px; border-radius:4px;">🔇 Muted until ${new Date(user.muted_until).toLocaleDateString()}</span></div>` : '';
        const bannedInfo = user.banned ? `<div style="margin-bottom: 5px;"><span style="background:#ff4444; padding:2px 8px; border-radius:4px;">🚫 Banned</span></div>` : '';
        const warningCount = user.warnings.length;
        const warningBadge = warningCount > 0 ? `<span class="gb-badge" style="background:#ffaa00;">⚠️ ${warningCount} warning(s)</span>` : '';
        return `
          <div class="gb-card" style="border-left: 4px solid ${user.is_shadow_banned ? '#ff4444' : (isMuted ? '#ffaa00' : (user.banned ? '#ff4444' : '#ffaa00'))}; margin-bottom: 15px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
              <h3 style="margin: 0; color: #fff;">${escapeHTML(user.username || 'Unknown')}</h3>
              <div>
                <span class="gb-badge" style="background:${user.trust_score < 30 ? '#ff4444' : '#ffaa00'};">Trust: ${user.trust_score || 0}</span>
                ${warningBadge}
              </div>
            </div>
            <div style="display: flex; gap: 20px; margin-bottom: 15px; color: #ccc; font-size: 14px;">
              <span>📧 ${escapeHTML(user.email || 'No email')}</span>
              <span>🚩 Spam: ${user.spam_flags || 0}</span>
              <span>📤 Uploads: ${user.upload_count || 0}</span>
            </div>
            ${muteInfo}
            ${bannedInfo}
            <div style="margin-bottom: 15px; padding: 8px 12px; background: ${user.is_shadow_banned ? '#2a1a1a' : '#1a2a1a'}; border-radius: 5px; color: ${user.is_shadow_banned ? '#ff8888' : '#00ff88'};">
              ${user.is_shadow_banned ? '🔇 Shadow Banned' : (user.banned ? '🚫 Banned' : '✅ Active')}
            </div>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
              <button onclick="warnUser('${user.id}')" class="gb-btn gb-btn-warning">⚠️ Warn</button>
              ${!user.is_shadow_banned && !user.banned ? 
                `<button onclick="shadowBanUser('${user.id}')" class="gb-btn gb-btn-warning">🔇 Shadow Ban</button>` : 
                (user.is_shadow_banned ? `<button onclick="unbanUser('${user.id}')" class="gb-btn gb-btn-primary">✓ Unban (Shadow)</button>` : '')
              }
              ${user.banned ? 
                `<button onclick="unbanUser('${user.id}')" class="gb-btn gb-btn-primary">✓ Unban</button>` : 
                ''
              }
              ${isMuted ? 
                `<button onclick="unmuteUser('${user.id}')" class="gb-btn gb-btn-secondary">🔊 Unmute</button>` : 
                ''
              }
              <button onclick="verifyUser('${user.id}')" class="gb-btn gb-btn-secondary" ${user.is_verified ? 'disabled' : ''}>${user.is_verified ? '✅ Verified' : '✅ Verify'}</button>
              <button onclick="resetTrustScore('${user.id}')" class="gb-btn gb-btn-secondary">↻ Reset</button>
            </div>
          </div>
        `;
      }).join('');
    } catch (err) {
      console.error("Failed to load risky users:", err);
      box.innerHTML = '<div class="gb-error">Failed to load risky users</div>';
    }
  };

  async function loadFlaggedMods() {
    const box = document.getElementById("flagged");
    if (!box || !await isAdmin()) return;
    try {
      const { data, error } = await supabaseClient
        .from("mods2")
        .select(`id, title, user_id, author_name, risk_score, scan_status, scan_reason, created_at, download_count, view_count`)
        .or('risk_score.gt.70,scan_status.eq.quarantined')
        .order("risk_score", { ascending: false })
        .limit(20);
      if (error) throw error;
      if (!data?.length) { box.innerHTML = '<div class="gb-no-results">No flagged mods</div>'; return; }
      box.innerHTML = data.map(mod => `
        <div class="gb-card" style="border-left: 4px solid #ff4444; margin-bottom: 15px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;"><h3 style="margin: 0; color: #fff;">${escapeHTML(mod.title)}</h3><span class="gb-badge" style="background:#ff4444;">⚠️ RISK ${mod.risk_score || 0}</span></div>
          <div style="display: flex; gap: 20px; margin-bottom: 15px; color: #ccc; font-size: 14px;"><span>👤 ${escapeHTML(mod.author_name || 'Unknown')}</span><span>📥 ${mod.download_count || 0}</span><span>📅 ${new Date(mod.created_at).toLocaleDateString()}</span></div>
          <p style="color: #ffaa00; margin-bottom: 15px;">${escapeHTML(mod.scan_reason || 'High risk score')}</p>
          <div style="display: flex; gap: 10px;"><button onclick="quarantineMod('${mod.id}')" class="gb-btn gb-btn-warning">⚠️ Quarantine</button><button onclick="deleteMod('${mod.id}')" class="gb-btn gb-btn-danger">🗑️ Delete</button><button onclick="clearFlags('${mod.id}')" class="gb-btn gb-btn-secondary">✓ Clear</button></div>
        </div>
      `).join('');
    } catch (err) {
      console.error("Failed to load flagged mods:", err);
      box.innerHTML = '<div class="gb-error">Failed to load flagged mods</div>';
    }
  }

  async function loadQuarantineMods() {
    const box = document.getElementById("quarantineMods");
    if (!box || !await isAdmin()) return;
    try {
      const { data, error } = await supabaseClient
        .from("mods2")
        .select(`id, title, user_id, author_name, scan_reason, risk_score, created_at, download_count`)
        .eq("quarantine", true)
        .order("created_at", { ascending: false });
      if (error) throw error;
      if (!data?.length) { box.innerHTML = '<div class="gb-no-results">No quarantined mods</div>'; return; }
      box.innerHTML = data.map(mod => `
        <div class="gb-card" style="border-left: 4px solid #ffaa00; margin-bottom: 15px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;"><h3 style="margin: 0; color: #fff;">${escapeHTML(mod.title)}</h3><span class="gb-badge" style="background:#ffaa00;">☣️ Quarantined</span></div>
          <div style="display: flex; gap: 20px; margin-bottom: 15px; color: #ccc; font-size: 14px;"><span>👤 ${escapeHTML(mod.author_name || 'Unknown')}</span><span>📥 ${mod.download_count || 0}</span><span>📅 ${new Date(mod.created_at).toLocaleDateString()}</span></div>
          <p style="color: #ffaa00; margin-bottom: 15px;">${escapeHTML(mod.scan_reason || 'Quarantined by admin')}</p>
          <div style="display: flex; gap: 10px;"><button onclick="approveMod('${mod.id}')" class="gb-btn gb-btn-primary">✅ Release</button><button onclick="deleteMod('${mod.id}')" class="gb-btn gb-btn-danger">🗑️ Delete</button></div>
        </div>
      `).join('');
    } catch (err) {
      console.error("Failed to load quarantine mods:", err);
      box.innerHTML = '<div class="gb-error">Failed to load quarantine mods</div>';
    }
  }

  async function loadPendingMods() {
    const box = document.getElementById("pendingMods");
    if (!box || !await isModerator()) return;
    try {
      const { data, error } = await supabaseClient
        .from("mods2")
        .select(`id, title, description, user_id, author_name, version, baldi_version, created_at, file_size, risk_score, scan_status, scan_reason, tags`)
        .eq("approved", false)
        .eq("quarantine", false)
        .order("created_at", { ascending: true })
        .limit(50);
      if (error) throw error;
      if (!data?.length) { box.innerHTML = '<div class="gb-no-results">No pending mods</div>'; return; }
      box.innerHTML = data.map(mod => `
        <div class="gb-card review" style="margin-bottom: 20px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;"><h3 style="margin: 0; color: #00ff88;">${escapeHTML(mod.title)}</h3><span class="gb-badge">v${escapeHTML(mod.version || '1.0.0')}</span></div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px; padding: 15px; background: #1a1a1a; border-radius: 8px;">
            <div><strong style="display: block; color: #fff; margin-bottom: 5px;">Author</strong><span style="color: #ccc;">${escapeHTML(mod.author_name || 'Unknown')}</span></div>
            <div><strong style="display: block; color: #fff; margin-bottom: 5px;">Baldi Version</strong><span style="color: #ccc;">${escapeHTML(mod.baldi_version || 'Any')}</span></div>
            <div><strong style="display: block; color: #fff; margin-bottom: 5px;">Size</strong><span style="color: #ccc;">${formatFileSize(mod.file_size || 0)}</span></div>
            <div><strong style="display: block; color: #fff; margin-bottom: 5px;">Uploaded</strong><span style="color: #ccc;">${new Date(mod.created_at).toLocaleDateString()}</span></div>
          </div>
          <div style="margin-bottom: 15px;"><span>Risk Score: </span><span class="gb-badge" style="background:${mod.risk_score > 50 ? '#ff4444' : mod.risk_score > 20 ? '#ffaa00' : '#00ff88'};">${mod.risk_score || 0}/100</span></div>
          <div style="margin-bottom: 15px; padding: 15px; background: #1a1a1a; border-radius: 8px;"><strong style="display: block; color: #fff; margin-bottom: 10px;">Description</strong><p style="color: #ccc; margin: 0; line-height: 1.6;">${escapeHTML(mod.description.substring(0, 300))}${mod.description.length > 300 ? '...' : ''}</p></div>
          ${mod.scan_reason ? `<div style="margin-bottom: 15px; padding: 15px; background: #332200; border-left: 4px solid #ffaa00; border-radius: 4px;"><strong style="display: block; color: #ffaa00; margin-bottom: 10px;">🔍 Scan Notes</strong><p style="color: #fff; margin: 0;">${escapeHTML(mod.scan_reason)}</p></div>` : ''}
          <div style="display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap;">
            <button onclick="approveMod('${mod.id}')" class="gb-btn gb-btn-primary">✅ Approve</button>
            <button onclick="rejectMod('${mod.id}')" class="gb-btn gb-btn-danger">❌ Reject</button>
            <button onclick="quarantineMod('${mod.id}')" class="gb-btn gb-btn-warning">⚠️ Quarantine</button>
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.error("Failed to load pending mods:", err);
      box.innerHTML = '<div class="gb-error">Failed to load pending mods</div>';
    }
  }

  async function loadReportedMods() {
    const box = document.getElementById("reportedMods");
    if (!box || !await isModerator()) return;
    try {
      const { data, error } = await supabaseClient
        .from("mods2")
        .select(`id, title, user_id, author_name, reported_by, reported_at, scan_reason, created_at, download_count`)
        .eq("reported", true)
        .order("reported_at", { ascending: false });
      if (error) throw error;
      if (!data?.length) { box.innerHTML = '<div class="gb-no-results">No reported mods</div>'; return; }
      box.innerHTML = data.map(mod => `
        <div class="gb-card" style="border-left: 4px solid #ff4444; margin-bottom: 15px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;"><h3 style="margin: 0; color: #fff;">${escapeHTML(mod.title)}</h3><span class="gb-badge" style="background:#ff4444;">🚩 Reported</span></div>
          <div style="display: flex; gap: 20px; margin-bottom: 15px; color: #ccc; font-size: 14px;"><span>👤 ${escapeHTML(mod.author_name || 'Unknown')}</span><span>📥 ${mod.download_count || 0}</span><span>📅 ${new Date(mod.reported_at || mod.created_at).toLocaleDateString()}</span></div>
          <p style="color: #ffaa00; margin-bottom: 15px;">${escapeHTML(mod.scan_reason || 'User reported')}</p>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <button onclick="quarantineMod('${mod.id}')" class="gb-btn gb-btn-warning">⚠️ Quarantine</button>
            <button onclick="deleteMod('${mod.id}')" class="gb-btn gb-btn-danger">🗑️ Delete</button>
            <button onclick="clearReport('${mod.id}')" class="gb-btn gb-btn-secondary">✓ Clear</button>
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.error("Failed to load reported mods:", err);
      box.innerHTML = '<div class="gb-error">Failed to load reported mods</div>';
    }
  }

  // Admin Action Functions
  async function approveMod(id) {
    if (!await isModerator()) return;
    if (!confirm('Approve this mod? It will be public immediately.')) return;
    try {
      const { error } = await supabaseClient.from("mods2").update({ approved: true, quarantine: false, scan_status: 'approved', updated_at: new Date().toISOString() }).eq("id", id);
      if (error) throw error;
      showNotification("✅ Mod approved successfully", "success");
      if (typeof loadPendingMods === 'function') loadPendingMods();
      if (typeof loadReportedMods === 'function') loadReportedMods();
    } catch (err) {
      console.error("Failed to approve mod:", err);
      showNotification("Failed to approve mod", "error");
    }
  }

  async function rejectMod(id) {
    if (!await isModerator()) return;
    const reason = prompt('Reason for rejection:');
    if (!reason) return;
    try {
      const { error } = await supabaseClient.from("mods2").update({ approved: false, scan_status: 'rejected', scan_reason: reason, updated_at: new Date().toISOString() }).eq("id", id);
      if (error) throw error;
      showNotification("Mod rejected", "info");
      if (typeof loadPendingMods === 'function') loadPendingMods();
    } catch (err) {
      console.error("Failed to reject mod:", err);
      showNotification("Failed to reject mod", "error");
    }
  }

  async function quarantineMod(id) {
    if (!await isModerator()) return;
    if (!confirm('Quarantine this mod? It will be hidden from users.')) return;
    try {
      const { error } = await supabaseClient.from("mods2").update({ quarantine: true, approved: false, scan_status: 'quarantined', updated_at: new Date().toISOString() }).eq("id", id);
      if (error) throw error;
      showNotification("Mod quarantined", "warning");
      if (typeof loadPendingMods === 'function') loadPendingMods();
      if (typeof loadReportedMods === 'function') loadReportedMods();
      if (typeof loadQuarantineMods === 'function') loadQuarantineMods();
    } catch (err) {
      console.error("Failed to quarantine mod:", err);
      showNotification("Failed to quarantine mod", "error");
    }
  }

async function deleteMod(id) {
  if (!await isModerator()) return;
  if (!confirm('⚠️ Permanently delete this mod? This cannot be undone.')) return;

  try {
    // Fetch mod data to get screenshot URLs
    const { data: mod, error: fetchError } = await supabaseClient
      .from("mods2")
      .select("screenshots, file_storage_path")
      .eq("id", id)
      .single();

    if (fetchError) throw fetchError;

    console.log('Deleting mod, screenshots:', mod?.screenshots);

    // Delete the mod record from database
    const { error } = await supabaseClient
      .from("mods2")
      .delete()
      .eq("id", id);

    if (error) throw error;

    // Delete all screenshots from storage
    if (mod?.screenshots && Array.isArray(mod.screenshots)) {
      for (const screenshot of mod.screenshots) {
        const url = screenshot.url;
        if (url && url.includes('supabase.co')) {
          // Extract path: everything after 'mod-screenshots/'
          const match = url.match(/\/mod-screenshots\/(.+)$/);
          if (match && match[1]) {
            const path = match[1];
            console.log(`Attempting to delete screenshot: ${path}`);
            try {
              const { error: deleteError } = await supabaseClient.storage
                .from('mod-screenshots')
                .remove([path]);
              if (deleteError) {
                console.error('Failed to delete screenshot:', deleteError);
              } else {
                console.log('Successfully deleted:', path);
              }
            } catch (storageErr) {
              console.error('Exception deleting screenshot:', storageErr);
            }
          } else {
            console.warn('Could not extract path from URL:', url);
          }
        }
      }
    }

    // Delete mod file if stored in Supabase (optional)
    if (mod?.file_storage_path) {
      try {
        await supabaseClient.storage.from("baldi-mods").remove([mod.file_storage_path]);
      } catch (storageErr) {
        console.warn("Failed to delete mod file from storage:", storageErr);
      }
    }

    showNotification("✅ Mod deleted", "success");
    if (typeof loadPendingMods === 'function') loadPendingMods();
    if (typeof loadReportedMods === 'function') loadReportedMods();
    if (typeof loadMyMods === 'function') loadMyMods();
  } catch (err) {
    console.error("Failed to delete mod:", err);
    showNotification("Failed to delete mod", "error");
  }
}
  async function clearReport(id) {
    if (!await isModerator()) return;
    try {
      const { error } = await supabaseClient.from("mods2").update({ reported: false, reported_by: null, reported_at: null, updated_at: new Date().toISOString() }).eq("id", id);
      if (error) throw error;
      showNotification("Report cleared", "success");
      if (typeof loadReportedMods === 'function') loadReportedMods();
    } catch (err) {
      console.error("Failed to clear report:", err);
      showNotification("Failed to clear report", "error");
    }
  }

  async function reportMod(id) {
    const user = await getCurrentUser();
    if (!user) { return showNotification("Please login to report mods", "error"); }
    const modal = document.getElementById('reportModal');
    if (modal) {
      document.getElementById('reportModId').value = id;
      modal.style.display = 'flex';
    } else {
      if (!confirm('Report this mod? Moderators will review it.')) return;
      try {
        const { error } = await supabaseClient.from("mods2").update({ reported: true, reported_by: user.id, reported_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("id", id);
        if (error) throw error;
        showNotification("✅ Mod reported to moderators", "success");
      } catch (err) {
        console.error("Failed to report mod:", err);
        showNotification("Failed to report mod", "error");
      }
    }
  }

  async function shadowBanUser(userId) {
    if (!await isAdmin()) return;
    if (!confirm('⚠️ Shadow ban this user? Their content will be hidden.')) return;
    try {
      const { error } = await supabaseClient.from("profiles").update({ is_shadow_banned: true, trust_score: 0, updated_at: new Date().toISOString() }).eq("id", userId);
      if (error) throw error;
      showNotification("User shadow banned", "success");
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error("Failed to shadow ban user:", err);
      showNotification("Failed to shadow ban user", "error");
    }
  }

  async function removeShadowBan(userId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient.from("profiles").update({ is_shadow_banned: false, trust_score: 50, updated_at: new Date().toISOString() }).eq("id", userId);
      if (error) throw error;
      showNotification("Shadow ban removed", "success");
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error("Failed to remove shadow ban:", err);
      showNotification("Failed: " + (err.message || "Unknown error"), "error");
    }
  }

  async function verifyUser(userId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient.from("profiles").update({ is_verified: true, trust_score: 100, updated_at: new Date().toISOString() }).eq("id", userId);
      if (error) throw error;
      showNotification("User verified", "success");
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error("Failed to verify user:", err);
      showNotification("Failed to verify user", "error");
    }
  }

  async function resetTrustScore(userId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient.from("profiles").update({ trust_score: 100, spam_flags: 0, updated_at: new Date().toISOString() }).eq("id", userId);
      if (error) throw error;
      showNotification("Trust score reset", "success");
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error("Failed to reset trust score:", err);
      showNotification("Failed to reset trust score", "error");
    }
  }

  async function clearFlags(modId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient.from("mods2").update({ risk_score: 0, scan_status: 'clean', quarantine: false, updated_at: new Date().toISOString() }).eq("id", modId);
      if (error) throw error;
      showNotification("Flags cleared", "success");
      if (typeof loadFlaggedMods === 'function') loadFlaggedMods();
      if (typeof loadQuarantineMods === 'function') loadQuarantineMods();
    } catch (err) {
      console.error("Failed to clear flags:", err);
      showNotification("Failed to clear flags", "error");
    }
  }

  // =========================
  // BAN / UNBAN
  // =========================
  async function banUser(userId, reason = '') {
    if (!await isAdmin()) return;
    if (!confirm('Ban this user? They will not be able to log in.')) return;
    try {
      const { error } = await supabaseClient
        .from('profiles')
        .update({ 
          banned: true, 
          banned_at: new Date().toISOString(),
          trust_score: 0 
        })
        .eq('id', userId);
      if (error) throw error;
      showNotification('User banned', 'success');
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error('Failed to ban user:', err);
      showNotification('Failed to ban user', 'error');
    }
  }

  async function unbanUser(userId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient
        .from('profiles')
        .update({ banned: false, banned_at: null, trust_score: 50 })
        .eq('id', userId);
      if (error) throw error;
      showNotification('User unbanned', 'success');
      if (typeof loadRiskUsers === 'function') loadRiskUsers();
    } catch (err) {
      console.error('Failed to unban user:', err);
      showNotification('Failed to unban user', 'error');
    }
  }

  // =========================
  // COMMENT DELETION REQUESTS
  // =========================
  async function createDeletionRequest(commentId, reason = '') {
    const mod = await getCurrentUser();
    if (!mod || !await isModerator()) return;
    try {
      const { error } = await supabaseClient
        .from('comment_deletion_requests')
        .insert({
          comment_id: commentId,
          moderator_id: mod.id,
          reason: reason,
          status: 'pending'
        });
      if (error) throw error;
      showNotification('Deletion request submitted to admin', 'success');
    } catch (err) {
      console.error('Failed to create deletion request:', err);
      showNotification('Failed to create request', 'error');
    }
  }

  async function approveDeletionRequest(requestId) {
    if (!await isAdmin()) return;
    try {
      const { data: request, error: fetchError } = await supabaseClient
        .from('comment_deletion_requests')
        .select('comment_id')
        .eq('id', requestId)
        .single();
      if (fetchError) throw fetchError;

      const { error: deleteError } = await supabaseClient
        .from('comments')
        .delete()
        .eq('id', request.comment_id);
      if (deleteError) throw deleteError;

      const { error: updateError } = await supabaseClient
        .from('comment_deletion_requests')
        .update({ status: 'approved', updated_at: new Date().toISOString() })
        .eq('id', requestId);
      if (updateError) throw updateError;

      showNotification('Comment deleted', 'success');
      if (typeof loadDeletionRequests === 'function') loadDeletionRequests();
    } catch (err) {
      console.error('Failed to approve deletion:', err);
      showNotification('Failed to approve deletion', 'error');
    }
  }

  async function rejectDeletionRequest(requestId) {
    if (!await isAdmin()) return;
    try {
      const { error } = await supabaseClient
        .from('comment_deletion_requests')
        .update({ status: 'rejected', updated_at: new Date().toISOString() })
        .eq('id', requestId);
      if (error) throw error;
      showNotification('Request rejected', 'success');
      if (typeof loadDeletionRequests === 'function') loadDeletionRequests();
    } catch (err) {
      console.error('Failed to reject request:', err);
      showNotification('Failed to reject request', 'error');
    }
  }

  async function loadDeletionRequests() {
    const box = document.getElementById('deletionRequests');
    if (!box) return;
    try {
      const { data, error } = await supabaseClient
        .from('comment_deletion_requests')
        .select(`
          *,
          comments (id, content, user_id, profiles:user_id (username), mods2 (title, id)),
          profiles:moderator_id (username)
        `)
        .eq('status', 'pending')
        .order('created_at', { ascending: true });
      if (error) throw error;
      if (!data?.length) {
        box.innerHTML = '<div class="gb-no-results">No pending deletion requests</div>';
        return;
      }
      box.innerHTML = data.map(req => `
        <div class="gb-card" style="border-left: 4px solid #ffaa00; margin-bottom: 15px;">
          <div style="margin-bottom: 10px;">
            <strong>Comment:</strong> ${escapeHTML(req.comments?.content?.substring(0,100))}...<br>
            <strong>Author:</strong> ${escapeHTML(req.comments?.profiles?.username || 'Unknown')}<br>
            <strong>In mod:</strong> <a href="mod.html?id=${req.comments?.mods2?.id}" target="_blank">${escapeHTML(req.comments?.mods2?.title || 'Unknown')}</a><br>
            <strong>Requested by:</strong> ${escapeHTML(req.profiles?.username || 'Unknown')}<br>
            <strong>Reason:</strong> ${escapeHTML(req.reason || 'No reason')}<br>
            <strong>Date:</strong> ${new Date(req.created_at).toLocaleString()}
          </div>
          <div style="display: flex; gap: 10px;">
            <button onclick="approveDeletionRequest('${req.id}')" class="gb-btn gb-btn-primary">✅ Approve</button>
            <button onclick="rejectDeletionRequest('${req.id}')" class="gb-btn gb-btn-danger">❌ Reject</button>
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.error('Failed to load deletion requests:', err);
      box.innerHTML = '<div class="gb-error">Failed to load requests</div>';
    }
  }
  /* =========================
     COMMENTS & FAVORITES
  ========================= */

  async function loadComments(modId) {
    const container = document.getElementById('commentsContainer');
    if (!container) return;

    try {
      const { data: comments, error } = await supabaseClient
        .from('comments')
        .select('*')
        .eq('mod_id', modId)
        .order('created_at', { ascending: true });

      if (error) throw error;

      const userIds = [...new Set(comments.map(c => c.user_id))];
      const { data: profiles } = await supabaseClient
        .from('profiles')
        .select('id, username, is_shadow_banned, banned')
        .in('id', userIds);

      const profileMap = {};
      const shadowBannedMap = {};
      const bannedMap = {};
      profiles?.forEach(p => {
        profileMap[p.id] = p.username;
        shadowBannedMap[p.id] = p.is_shadow_banned;
        bannedMap[p.id] = p.banned;
      });

      let reactionsMap = {};
      if (comments.length) {
        const { data: reactions } = await supabaseClient
          .from('comment_reactions')
          .select('comment_id, user_id')
          .in('comment_id', comments.map(c => c.id));
        reactionsMap = reactions?.reduce((acc, r) => {
          if (!acc[r.comment_id]) acc[r.comment_id] = [];
          acc[r.comment_id].push(r.user_id);
          return acc;
        }, {}) || {};
      }

      const user = await getCurrentUser();
      const isModOrAdmin = user && (await isModerator());

      const topLevel = comments.filter(c => !c.parent_id);
      const replies = comments.filter(c => c.parent_id);

      container.innerHTML = topLevel.map(comment => {
        const isShadowBanned = shadowBannedMap[comment.user_id];
        const isBanned = bannedMap[comment.user_id];
        const shouldHide = (isShadowBanned || isBanned) && !isModOrAdmin;
        return renderComment(comment, replies.filter(r => r.parent_id === comment.id), profileMap, reactionsMap, user, shouldHide, isModOrAdmin);
      }).join('');

    } catch (err) {
      console.error('Failed to load comments:', err);
      container.innerHTML = '<div class="gb-error">Failed to load comments</div>';
    }
  }

  function renderComment(comment, replies, profileMap, reactionsMap, user, hidden = false, canModerate = false) {
    const isAuthor = user && user.id === comment.user_id;
    const showDelete = isAuthor || canModerate;

    const reactionCount = reactionsMap[comment.id]?.length || 0;
    const userReacted = user && reactionsMap[comment.id]?.includes(user.id);

    if (hidden) {
      return `
        <div class="gb-comment" data-comment-id="${comment.id}" id="comment-${comment.id}">
          <div class="gb-comment-avatar">${profileMap[comment.user_id]?.charAt(0).toUpperCase() || '?'}</div>
          <div class="gb-comment-content">
            <div class="gb-comment-header">
              <span class="gb-comment-author">${escapeHTML(profileMap[comment.user_id] || 'Unknown')}</span>
              <span class="gb-comment-date">${new Date(comment.created_at).toLocaleString()}</span>
              <span class="gb-badge" style="background:#ff4444;">🔇 Hidden</span>
            </div>
            <div class="gb-comment-text" style="color: #666; font-style: italic;">
              This comment is hidden due to user restriction.
              <button onclick="revealComment('${comment.id}')" class="gb-btn gb-btn-small">Reveal</button>
            </div>
            <div class="gb-comment-footer">
              <button onclick="toggleCommentReaction('${comment.id}')" class="gb-btn gb-btn-small ${userReacted ? 'gb-btn-primary' : 'gb-btn-secondary'}">❤️ ${reactionCount}</button>
              <button onclick="openCommentReportModal('${comment.id}')" class="gb-btn gb-btn-small gb-btn-secondary">🚩 Report</button>
            </div>
          </div>
        </div>
      `;
    }

    return `
      <div class="gb-comment" data-comment-id="${comment.id}" id="comment-${comment.id}">
        <div class="gb-comment-avatar">${profileMap[comment.user_id]?.charAt(0).toUpperCase() || '?'}</div>
        <div class="gb-comment-content">
          <div class="gb-comment-header">
            <span class="gb-comment-author"><a href="profile.html?id=${comment.user_id}" style="color: inherit; text-decoration: none;">${escapeHTML(profileMap[comment.user_id] || 'Unknown')}</a></span>
            <span class="gb-comment-date">${new Date(comment.created_at).toLocaleString()}</span>
            ${comment.updated_at !== comment.created_at ? '<span class="gb-comment-edited">(edited)</span>' : ''}
          </div>
          <div class="gb-comment-text" id="comment-text-${comment.id}">${escapeHTML(comment.content)}</div>
          ${showDelete ? `
            <div class="gb-comment-actions">
              ${isAuthor ? `<button onclick="editComment('${comment.id}')" class="gb-btn gb-btn-small">Edit</button>` : ''}
              <button onclick="deleteComment('${comment.id}')" class="gb-btn gb-btn-small gb-btn-danger">Delete</button>
            </div>
          ` : ''}
          <div class="gb-comment-footer">
            <button onclick="toggleCommentReaction('${comment.id}')" class="gb-btn gb-btn-small ${userReacted ? 'gb-btn-primary' : 'gb-btn-secondary'}">❤️ ${reactionCount}</button>
            <button onclick="openCommentReportModal('${comment.id}')" class="gb-btn gb-btn-small gb-btn-secondary">🚩 Report</button>
          </div>
          ${replies.length ? `<div class="gb-comment-replies">${replies.map(r => renderComment(r, [], profileMap, reactionsMap, user, hidden, canModerate)).join('')}</div>` : ''}
        </div>
      </div>
    `;
  }

  window.revealComment = function(commentId) {
    const commentDiv = document.getElementById(`comment-${commentId}`);
    if (!commentDiv) return;
    supabaseClient
      .from('comments')
      .select('content')
      .eq('id', commentId)
      .single()
      .then(({ data, error }) => {
        if (error) return;
        const textDiv = commentDiv.querySelector('.gb-comment-text');
        if (textDiv) {
          textDiv.innerHTML = escapeHTML(data.content);
        }
      });
  };

  async function addComment(modId, content, parentId = null) {
    const user = await getCurrentUser();
    if (!user) {
      showNotification('Please login to comment', 'error');
      return;
    }
    if (!content.trim()) {
      showNotification('Comment cannot be empty', 'error');
      return;
    }

    // Mute check
    try {
      const { data: profile, error: profileError } = await supabaseClient
        .from('profiles')
        .select('muted_until')
        .eq('id', user.id)
        .single();

      if (profileError) {
        console.error('Mute check error:', profileError);
        showNotification('Could not verify mute status. Please try again.', 'error');
        return;
      }

      if (profile?.muted_until) {
        const muteDate = new Date(profile.muted_until);
        const now = new Date();
        if (muteDate > now) {
          showNotification(
            `You are muted and cannot comment until ${muteDate.toLocaleDateString()}`,
            'error'
          );
          return;
        }
      }
    } catch (err) {
      console.error('Unexpected mute check error:', err);
      showNotification('Error checking mute status. Please try again.', 'error');
      return;
    }

    // Filter bad words
    const filteredContent = filterBadWords(content.trim());

    try {
      const { error } = await supabaseClient
        .from('comments')
        .insert({
          mod_id: modId,
          user_id: user.id,
          content: filteredContent,
          parent_id: parentId,
          created_at: new Date().toISOString()
        });

      if (error) throw error;

      showNotification('Comment added', 'success');
      document.getElementById('commentInput').value = '';
      loadComments(modId);
    } catch (err) {
      console.error('Failed to add comment:', err);
      showNotification('Failed to add comment: ' + err.message, 'error');
    }
  }

   async function editComment(commentId) {
    const commentDiv = document.getElementById(`comment-text-${commentId}`);
    const currentText = commentDiv.innerText;
    const newText = prompt('Edit your comment:', currentText);
    if (newText === null || newText.trim() === '') return;

    const filteredNew = filterBadWords(newText.trim());

    try {
      const { error } = await supabaseClient
        .from('comments')
        .update({ content: filteredNew, updated_at: new Date().toISOString() })
        .eq('id', commentId);
      if (error) throw error;
      showNotification('Comment updated', 'success');
      const modId = getQueryParam("id");
      if (modId) loadComments(modId);
    } catch (err) {
      console.error('Failed to edit comment:', err);
      showNotification('Failed to edit comment', 'error');
    }
  }
  async function deleteComment(commentId) {
    if (!confirm('Delete this comment?')) return;
    try {
      const { error } = await supabaseClient.from('comments').delete().eq('id', commentId);
      if (error) throw error;
      showNotification('Comment deleted', 'success');
      const modId = getQueryParam("id");
      if (modId) loadComments(modId);
    } catch (err) {
      console.error('Failed to delete comment:', err);
      showNotification('Failed to delete comment', 'error');
    }
  }

  async function toggleCommentReaction(commentId) {
    const user = await getCurrentUser();
    if (!user) { showNotification('Please login to react', 'error'); return; }

    try {
      const { data: existing } = await supabaseClient
        .from('comment_reactions')
        .select('id')
        .eq('comment_id', commentId)
        .eq('user_id', user.id)
        .maybeSingle();

      if (existing) {
        const { error } = await supabaseClient.from('comment_reactions').delete().eq('id', existing.id);
        if (error) throw error;
      } else {
        const { error } = await supabaseClient.from('comment_reactions').insert({ comment_id: commentId, user_id: user.id });
        if (error) throw error;
      }
      const modId = getQueryParam("id");
      if (modId) loadComments(modId);
    } catch (err) {
      console.error('Failed to toggle reaction:', err);
      showNotification('Failed to update reaction', 'error');
    }
  }

  async function toggleFavorite(modId) {
    const user = await getCurrentUser();
    if (!user) { showNotification('Please login to favorite', 'error'); return; }

    try {
      const { data: existing } = await supabaseClient
        .from('favorites')
        .select('id')
        .eq('mod_id', modId)
        .eq('user_id', user.id)
        .maybeSingle();

      if (existing) {
        const { error } = await supabaseClient.from('favorites').delete().eq('id', existing.id);
        if (error) throw error;
        showNotification('Removed from favorites', 'success');
      } else {
        const { error } = await supabaseClient.from('favorites').insert({ mod_id: modId, user_id: user.id });
        if (error) throw error;
        showNotification('Added to favorites', 'success');
      }
      updateFavoriteButton(modId);
    } catch (err) {
      console.error('Failed to toggle favorite:', err);
      showNotification('Failed to update favorite', 'error');
    }
  }

  async function checkFavorite(modId) {
    const user = await getCurrentUser();
    if (!user) return false;
    const { data } = await supabaseClient.from('favorites').select('id').eq('mod_id', modId).eq('user_id', user.id).maybeSingle();
    return !!data;
  }

  async function updateFavoriteButton(modId) {
    const btn = document.getElementById('favoriteBtn');
    if (!btn) return;
    const isFav = await checkFavorite(modId);
    btn.innerHTML = isFav ? '❤️ Unfavorite' : '🤍 Favorite';
    btn.className = isFav ? 'gb-btn gb-btn-primary gb-btn-large' : 'gb-btn gb-btn-outline gb-btn-large';
  }

  /* =========================
     PUBLIC PROFILE
  ========================= */

  async function loadPublicProfile(userId) {
    const container = document.getElementById('profile-content');
    if (!container) return;
    try {
      const { data: profile, error } = await supabaseClient.from('profiles').select('*').eq('id', userId).single();
      if (error || !profile) { container.innerHTML = '<div class="gb-error">User not found</div>'; return; }

      if (profile.banned) {
        const user = await getCurrentUser();
        const isModOrAdmin = user && (await isModerator());
        if (!isModOrAdmin) {
          container.innerHTML = '<div class="gb-error">This user has been banned.</div>';
          return;
        }
      }

      const user = await getCurrentUser();
      let isBuddy = false, isSubscribed = false;
      if (user) {
        const [buddyRes, subRes] = await Promise.all([
          supabaseClient.from('buddies').select('id').eq('user_id', user.id).eq('buddy_id', userId).maybeSingle(),
          supabaseClient.from('subscriptions').select('id').eq('subscriber_id', user.id).eq('target_id', userId).maybeSingle()
        ]);
        isBuddy = !!buddyRes.data;
        isSubscribed = !!subRes.data;
      }
      const joinDate = new Date(profile.join_date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
      let trustColor = profile.trust_score >= 80 ? '#00ff88' : profile.trust_score >= 50 ? '#ffaa00' : '#ff4444';
      let roleBadge = profile.role === 'admin' ? '<span class="gb-profile-badge admin">👑 ADMIN</span>' :
                      profile.role === 'moderator' ? '<span class="gb-profile-badge moderator">🛡️ MOD</span>' :
                      profile.is_verified ? '<span class="gb-profile-badge verified">✅ VERIFIED</span>' : '<span class="gb-profile-badge">👤 USER</span>';
      container.innerHTML = `
        <div class="gb-profile-container">
          <div class="gb-profile-sidebar">
            <div class="gb-profile-cover"></div>
            <div class="gb-profile-avatar">${profile.username?.charAt(0).toUpperCase() || '?'}</div>
            <div class="gb-profile-info">
              <h2 class="gb-profile-name">${escapeHTML(profile.username)}</h2>
              ${roleBadge}
              <div class="gb-profile-stats">
                <div class="gb-stat"><span class="gb-stat-value">${profile.upload_count || 0}</span><span class="gb-stat-label">Uploads</span></div>
                <div class="gb-stat"><span class="gb-stat-value">${profile.download_count || 0}</span><span class="gb-stat-label">Downloads</span></div>
                <div class="gb-stat"><span class="gb-stat-value join-date">${joinDate}</span><span class="gb-stat-label">Joined</span></div>
              </div>
              <div class="gb-trust-score">
                <div class="gb-trust-header"><span>Trust Score</span><span style="color:${trustColor};">${profile.trust_score}%</span></div>
                <div class="gb-trust-bar"><div class="gb-trust-fill" style="width:${profile.trust_score}%; background:${trustColor};"></div></div>
              </div>
              <div class="gb-profile-bio"><h3>About</h3><p>${escapeHTML(profile.bio || 'No bio.')}</p></div>
  ${user && user.id !== userId ? `
    <div class="gb-profile-actions">
      <a href="buddies.html?id=${userId}" class="gb-btn gb-btn-outline gb-btn-block">👥 Buddies</a>
      <a href="subscribers.html?id=${userId}" class="gb-btn gb-btn-outline gb-btn-block">👤 Subscribers</a>
      <button onclick="toggleBuddy('${userId}')" class="gb-btn ${isBuddy ? 'gb-btn-primary' : 'gb-btn-outline'} gb-btn-block" id="buddyBtn-${userId}">${isBuddy ? '✓ Buddy' : '+ Add Buddy'}</button>
      <button onclick="toggleSubscribe('${userId}')" class="gb-btn ${isSubscribed ? 'gb-btn-primary' : 'gb-btn-outline'} gb-btn-block" id="subBtn-${userId}">${isSubscribed ? '🔔 Subscribed' : '🔔 Subscribe'}</button>
    </div>
  ` : ''}
            </div>
          </div>
          <div class="gb-profile-main">
            <h3>${escapeHTML(profile.username)}'s Mods</h3>
            <div id="userMods" class="gb-mod-grid" style="grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));"></div>
          </div>
        </div>
      `;
      const { data: mods } = await supabaseClient.from('mods2').select('*').eq('user_id', userId).eq('approved', true).order('created_at', { ascending: false });
      const modsContainer = document.getElementById('userMods');
      if (mods && mods.length) {
        modsContainer.innerHTML = mods.map(mod => `
          <div class="gb-card" style="padding:15px;">
            <h4><a href="mod.html?id=${mod.id}" style="color:#00ff88;">${escapeHTML(mod.title)}</a></h4>
            <p>📥 ${mod.download_count || 0} | 👁️ ${mod.view_count || 0}</p>
            <p>${escapeHTML(mod.description.substring(0,100))}...</p>
          </div>
        `).join('');
      } else {
        modsContainer.innerHTML = '<p>No mods yet.</p>';
      }
    } catch (err) { console.error(err); container.innerHTML = '<div class="gb-error">Error loading profile</div>'; }
  }

  // =========================
  // PROFILE BUDDIES / SUBSCRIBERS (inline)
  // =========================

  async function loadProfileBuddies(userId) {
    const container = document.getElementById('profileBuddiesList');
    if (!container) return;
    container.innerHTML = '<div class="gb-loading-spinner"></div> Loading buddies...';
    try {
      const { data: buddies, error: buddiesError } = await supabaseClient
        .from('buddies')
        .select('buddy_id')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(24);

      if (buddiesError) throw buddiesError;

      if (!buddies || buddies.length === 0) {
        container.innerHTML = '<p class="gb-text-muted">No buddies yet.</p>';
        return;
      }

      const buddyIds = buddies.map(b => b.buddy_id);
      const { data: profiles, error: profilesError } = await supabaseClient
        .from('profiles')
        .select('id, username, trust_score, is_verified, role')
        .in('id', buddyIds);

      if (profilesError) throw profilesError;

      const profileMap = {};
      profiles.forEach(p => profileMap[p.id] = p);

      container.innerHTML = buddies.map(item => {
        const p = profileMap[item.buddy_id];
        return p ? renderUserCard(p, item.buddy_id) : '';
      }).join('');
    } catch (err) {
      console.error(err);
      container.innerHTML = '<div class="gb-error">Failed to load buddies</div>';
    }
  }

  async function loadProfileSubscribers(userId) {
    const container = document.getElementById('profileSubscribersList');
    if (!container) return;
    container.innerHTML = '<div class="gb-loading-spinner"></div> Loading subscribers...';
    try {
      const { data: subs, error: subsError } = await supabaseClient
        .from('subscriptions')
        .select('subscriber_id')
        .eq('target_id', userId)
        .order('created_at', { ascending: false })
        .limit(24);

      if (subsError) throw subsError;

      if (!subs || subs.length === 0) {
        container.innerHTML = '<p class="gb-text-muted">No subscribers yet.</p>';
        return;
      }

      const subscriberIds = subs.map(s => s.subscriber_id);
      const { data: profiles, error: profilesError } = await supabaseClient
        .from('profiles')
        .select('id, username, trust_score, is_verified, role')
        .in('id', subscriberIds);

      if (profilesError) throw profilesError;

      const profileMap = {};
      profiles.forEach(p => profileMap[p.id] = p);

      container.innerHTML = subs.map(item => {
        const p = profileMap[item.subscriber_id];
        return p ? renderUserCard(p, item.subscriber_id) : '';
      }).join('');
    } catch (err) {
      console.error(err);
      container.innerHTML = '<div class="gb-error">Failed to load subscribers</div>';
    }
  }

  function renderUserCard(profile, userId) {
    let badge = '';
    if (profile?.role === 'admin') badge = '<span class="gb-badge admin">ADMIN</span>';
    else if (profile?.role === 'moderator') badge = '<span class="gb-badge moderator">MOD</span>';
    else if (profile?.is_verified) badge = '<span class="gb-badge verified">VERIFIED</span>';
    return `
      <div class="gb-user-card">
        <div class="gb-user-avatar-lg">${profile?.username?.charAt(0).toUpperCase() || '?'}</div>
        <h3><a href="profile.html?id=${userId}" style="color:inherit; text-decoration:none;">${escapeHTML(profile?.username || 'Unknown')}</a></h3>
        ${badge}
        <p>⭐ ${profile?.trust_score || 0}</p>
      </div>
    `;
  }

   /* =========================
     EXPORT GLOBALS
  ========================= */
  window.signUp = signUp;
  window.signIn = signIn;
  window.logout = logout;
  window.uploadMod = uploadMod;
  window.loadMods = loadMods;
  window.trackDownload = trackDownload;
  window.reportMod = reportMod;
  window.checkAuthState = checkAuthState;
  window.getCurrentUser = getCurrentUser;
  window.isAdmin = isAdmin;
  window.isModerator = isModerator;
  window.guardUploadPage = guardUploadPage;
  window.guardProfilePage = guardProfilePage;
  window.guardAdminPage = guardAdminPage;
  window.guardAdminDashboard = guardAdminDashboard;
  window.showNotification = showNotification;
  window.formatFileSize = formatFileSize;
  window.escapeHTML = escapeHTML;
  window.setLoading = setLoading;

  window.loadAdminStats = loadAdminStats;
  window.loadFlaggedMods = loadFlaggedMods;
  window.loadRiskUsers = loadRiskUsers;
  window.loadQuarantineMods = loadQuarantineMods;
  window.loadPendingMods = loadPendingMods;
  window.loadReportedMods = loadReportedMods;
  window.approveMod = approveMod;
  window.rejectMod = rejectMod;
  window.quarantineMod = quarantineMod;
  window.deleteMod = deleteMod;
  window.clearReport = clearReport;
  window.shadowBanUser = shadowBanUser;
  window.removeShadowBan = removeShadowBan;
  window.verifyUser = verifyUser;
  window.resetTrustScore = resetTrustScore;
  window.clearFlags = clearFlags;

  window.loadProfilePage = loadProfilePage;
  window.loadMyMods = loadMyMods;
  window.updateProfile = updateProfile;
  window.loadUserStats = loadUserStats;
  window.loadModPage = loadModPage;

  window.loadComments = loadComments;
  window.addComment = addComment;
  window.editComment = editComment;
  window.deleteComment = deleteComment;
  window.toggleCommentReaction = toggleCommentReaction;
  window.toggleFavorite = toggleFavorite;
  window.checkFavorite = checkFavorite;
  window.updateFavoriteButton = updateFavoriteButton;
  window.renderComment = renderComment;

  window.toggleBuddy = toggleBuddy;
  window.toggleSubscribe = toggleSubscribe;
  window.toggleThank = toggleThank;
  window.loadPublicProfile = loadPublicProfile;
  window.loadProfileBuddies = loadProfileBuddies;
  window.loadProfileSubscribers = loadProfileSubscribers;
  window.renderUserCard = renderUserCard;
  window.warnUser = warnUser;
  window.unmuteUser = unmuteUser;
  window.unbanUser = unbanUser;
  window.banUser = banUser;
  window.createDeletionRequest = createDeletionRequest;
  window.approveDeletionRequest = approveDeletionRequest;
  window.rejectDeletionRequest = rejectDeletionRequest;
  window.loadDeletionRequests = loadDeletionRequests;
  window.revealComment = revealComment;

  window.supabaseClient = supabaseClient;

  document.addEventListener('DOMContentLoaded', checkAuthState);
})();