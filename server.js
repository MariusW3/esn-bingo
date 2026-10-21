const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

// ============================================================================
// KONFIGURATION & UMGEBUNGSVARIABLEN (In Portainer setzbar)
// ============================================================================
const PORT = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SUBMISSIONS_DIR = path.join(DATA_DIR, 'submissions');

// Anführungszeichen bereinigen, falls sie versehentlich in Portainer eingegeben wurden
function cleanEnvVal(val) {
  if (!val) return '';
  let s = String(val).trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1);
  }
  return s.trim();
}

const ADMIN_USER = cleanEnvVal(process.env.ADMIN_USER) || 'admin';
const ADMIN_PASSWORD = cleanEnvVal(process.env.ADMIN_PASSWORD);

// Verzeichnis für Einreichungen anlegen
fs.mkdirSync(SUBMISSIONS_DIR, { recursive: true });

// Geheimer Schlüssel für Session-Cookies (wird bei Serverstart zufällig erzeugt)
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

// Serverstart-Diagnose im Docker-Log
console.log('='.repeat(70));
console.log(`[CONFIG] ESN Bingo Server startet auf Port ${PORT}`);
console.log(`[CONFIG] ADMIN_USER: "${ADMIN_USER}"`);
if (!ADMIN_PASSWORD) {
  console.error('[CONFIG] ⛔ ADMIN_PASSWORD ist NICHT gesetzt! Der Admin-Zugang ist gesperrt.');
  console.error('[CONFIG] ⛔ Bitte setze in Portainer die Variable ADMIN_PASSWORD.');
} else {
  console.log(`[CONFIG] ADMIN_PASSWORD aktiv: JA (Länge: ${ADMIN_PASSWORD.length} Zeichen)`);
  if (ADMIN_PASSWORD.length < 8) {
    console.warn('[CONFIG] ⚠️  Passwort ist kürzer als 8 Zeichen.');
  }
}
console.log('='.repeat(70));

// ============================================================================
// SICHERHEITS-HELPER & RATE-LIMITING
// ============================================================================

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Brute-Force-Schutz (5 Fehlversuche -> 3 Minuten Sperre)
const failedLoginAttempts = new Map();

function isIpLocked(ip) {
  const entry = failedLoginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() < entry.lockedUntil) return true;
  failedLoginAttempts.delete(ip);
  return false;
}

function recordFailedLogin(ip) {
  const entry = failedLoginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  entry.count++;
  if (entry.count >= 5) {
    entry.lockedUntil = Date.now() + 3 * 60 * 1000; // 3 Minuten
    console.warn(`[SECURITY] IP ${ip} wurde für 3 Minuten gesperrt (5 Fehlversuche).`);
  }
  failedLoginAttempts.set(ip, entry);
}

function resetFailedLogin(ip) {
  failedLoginAttempts.delete(ip);
}

// Session Token Management (HMAC-signierte Cookies)
function createSessionToken() {
  const expires = Date.now() + 24 * 60 * 60 * 1000; // 24 Stunden gültig
  const payload = `${ADMIN_USER}:${expires}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64');
}

function verifySessionToken(token) {
  if (!token) return false;
  try {
    const raw = Buffer.from(token, 'base64').toString('utf-8');
    const [user, expiresStr, sig] = raw.split(':');
    const expires = parseInt(expiresStr, 10);
    if (!expires || Date.now() > expires) return false;
    const payload = `${user}:${expires}`;
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
    return timingSafeCompare(sig, expectedSig);
  } catch (e) {
    return false;
  }
}

function parseCookies(req) {
  const list = {};
  const header = req.headers['cookie'];
  if (!header) return list;
  header.split(';').forEach(c => {
    const parts = c.split('=');
    list[parts.shift().trim()] = decodeURI(parts.join('='));
  });
  return list;
}

// Prüft ob Nutzer angemeldet ist (entweder per Cookie oder per Basic Auth)
function isAuthenticated(req) {
  // 1. Session Cookie prüfen
  const cookies = parseCookies(req);
  if (cookies.esn_session && verifySessionToken(cookies.esn_session)) {
    return true;
  }

  // 2. Fallback: HTTP Basic Auth Header prüfen
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf-8');
      const colonIdx = credentials.indexOf(':');
      if (colonIdx !== -1) {
        const user = credentials.substring(0, colonIdx);
        const pass = credentials.substring(colonIdx + 1);
        if (timingSafeCompare(user, ADMIN_USER) && timingSafeCompare(pass, ADMIN_PASSWORD)) {
          return true;
        }
      }
    } catch (e) {}
  }

  return false;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function detectImageFormat(buffer) {
  if (!buffer || buffer.length < 8) return null;
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'jpg';
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return 'png';
  if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  return null;
}

// Login-Maske rendern
function renderLoginForm(errorMsg = '') {
  return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login — ESN Buddy Bingo</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --cyan: #00AEEF; --magenta: #EC008C; --navy: #2E3192;
      --bg: #EEF1F7; --card: #FFFFFF; --text: #141733; --border: #D8DFEE;
      --display: "Barlow Condensed", sans-serif; --body: "Inter", sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--body); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 16px; }
    .card { background: var(--card); border: 1px solid var(--border); border-top: 8px solid var(--magenta); border-radius: 8px; width: 100%; max-width: 400px; padding: 32px 28px; box-shadow: 0 4px 14px rgba(0,0,0,0.06); }
    h1 { font-family: var(--display); text-transform: uppercase; font-size: 26px; color: var(--navy); margin-bottom: 6px; letter-spacing: 0.04em; }
    p.sub { font-size: 13.5px; color: #64748b; margin-bottom: 22px; }
    .field { margin-bottom: 18px; }
    label { display: block; font-family: var(--display); text-transform: uppercase; font-size: 12px; font-weight: 700; letter-spacing: 0.1em; color: #475569; margin-bottom: 6px; }
    .input-wrap { position: relative; }
    input[type="text"], input[type="password"] { width: 100%; padding: 11px 12px; border: 2px solid var(--border); border-radius: 6px; font-size: 14.5px; font-family: var(--body); color: var(--text); outline: none; transition: border-color 0.2s; }
    input:focus { border-color: var(--navy); }
    .toggle-pwd { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 16px; opacity: 0.6; padding: 4px; }
    .toggle-pwd:hover { opacity: 1; }
    button.submit { width: 100%; padding: 12px; background: var(--navy); color: #fff; border: none; border-radius: 6px; font-family: var(--display); text-transform: uppercase; letter-spacing: 0.08em; font-size: 16px; font-weight: 700; cursor: pointer; margin-top: 8px; transition: background 0.2s; }
    button.submit:hover { background: #1d2060; }
    .error { background: #FEE2E2; border-left: 4px solid #EF4444; color: #991B1B; padding: 10px 12px; font-size: 13px; border-radius: 0 4px 4px 0; margin-bottom: 18px; }
    .back { display: block; text-align: center; margin-top: 20px; font-size: 13px; color: #64748b; text-decoration: none; }
    .back:hover { color: var(--navy); }
  </style>
</head>
<body>
  <div class="card">
    <h1>ESN Bingo Admin</h1>
    <p class="sub">Melde dich an, um Einreichungen und Fotos zu sehen.</p>
    ${errorMsg ? `<div class="error">${escapeHtml(errorMsg)}</div>` : ''}
    <form method="POST" action="/admin/login">
      <div class="field">
        <label for="username">Benutzername</label>
        <input type="text" id="username" name="username" value="${escapeHtml(ADMIN_USER)}" required autocomplete="username">
      </div>
      <div class="field">
        <label for="password">Passwort</label>
        <div class="input-wrap">
          <input type="password" id="password" name="password" required autocomplete="current-password" autofocus>
          <button type="button" class="toggle-pwd" id="eyeBtn" aria-label="Passwort anzeigen">👁️</button>
        </div>
      </div>
      <button type="submit" class="submit">Anmelden</button>
    </form>
    <a href="/" class="back">← Zurück zur Bingo-Seite</a>
  </div>
  <script>
    const eye = document.getElementById('eyeBtn');
    const pwd = document.getElementById('password');
    eye.addEventListener('click', () => {
      const isPwd = pwd.type === 'password';
      pwd.type = isPwd ? 'text' : 'password';
      eye.textContent = isPwd ? '🙈' : '👁️';
    });
  </script>
</body>
</html>`;
}

// ============================================================================
// HTTP SERVER & ROUTING
// ============================================================================
const server = http.createServer((req, res) => {
  setSecurityHeaders(res);
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const clientIp = getClientIp(req);

  // 1. Startseite: index.html
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const indexPath = path.join(__dirname, 'index.html');
    fs.readFile(indexPath, 'utf-8', (err, content) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('Fehler beim Laden von index.html: ' + err.message);
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    });
    return;
  }

  // 2. Healthcheck
  if (req.method === 'GET' && pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
  }

  // 3. Admin Logout
  if (req.method === 'GET' && pathname === '/admin/logout') {
    res.writeHead(302, {
      'Set-Cookie': 'esn_session=; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=0',
      'Location': '/admin'
    });
    return res.end();
  }

  // 4. Admin Web-Login (POST /admin/login)
  if (req.method === 'POST' && pathname === '/admin/login') {
    let body = [];
    req.on('data', chunk => body.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(body).toString('utf-8');
      const params = new URLSearchParams(raw);
      const user = (params.get('username') || '').trim();
      const pass = (params.get('password') || '').trim();

      if (!ADMIN_PASSWORD) {
        res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(renderLoginForm('Admin-Bereich gesperrt: Die Variable ADMIN_PASSWORD ist in Portainer nicht gesetzt.'));
      }

      if (isIpLocked(clientIp)) {
        res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(renderLoginForm('Zu viele Fehlversuche von dieser IP. Bitte 3 Minuten warten.'));
      }

      const userMatch = timingSafeCompare(user, ADMIN_USER);
      const passMatch = timingSafeCompare(pass, ADMIN_PASSWORD);

      if (userMatch && passMatch) {
        resetFailedLogin(clientIp);
        console.log(`[AUTH] Erfolgreicher Login von IP ${clientIp} als "${user}"`);
        const token = createSessionToken();
        res.writeHead(302, {
          'Set-Cookie': `esn_session=${token}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=86400`,
          'Location': '/admin'
        });
        return res.end();
      }

      // Fehlgeschlagener Login
      recordFailedLogin(clientIp);
      console.warn(`[AUTH] Login fehlgeschlagen von IP ${clientIp}:`);
      console.warn(`  - Eingegebener Benutzer: "${user}" (Erwartet: "${ADMIN_USER}" -> ${userMatch ? 'OK' : 'FALSCH'})`);
      console.warn(`  - Eingegebenes Passwort: Länge ${pass.length} Zeichen (Erwartet: Länge ${ADMIN_PASSWORD.length} Zeichen -> ${passMatch ? 'OK' : 'FALSCH'})`);

      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(renderLoginForm('Falscher Benutzername oder falsches Passwort. Beachte Groß-/Kleinschreibung.'));
    });
    return;
  }

  // 5. Admin: Geschütztes Foto abrufen (GET /admin/photo/:folder/:filename)
  if (req.method === 'GET' && pathname.startsWith('/admin/photo/')) {
    if (!isAuthenticated(req)) {
      res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Zugriff verweigert: Bitte vorher im Admin-Bereich anmelden.');
    }

    const parts = pathname.replace('/admin/photo/', '').split('/');
    if (parts.length !== 2) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Foto nicht gefunden.');
    }

    const folder = path.basename(parts[0]);
    const file = path.basename(parts[1]);

    if (!/^[a-zA-Z0-9_\-]+$/.test(folder) || !/^[a-zA-Z0-9_\-]+\.(jpg|jpeg|png|webp)$/.test(file)) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Ungültige Bildanforderung.');
    }

    const safeFilePath = path.resolve(SUBMISSIONS_DIR, folder, file);
    if (!safeFilePath.startsWith(path.resolve(SUBMISSIONS_DIR)) || !fs.existsSync(safeFilePath)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Foto existiert nicht.');
    }

    const mime = file.endsWith('.png') ? 'image/png' : (file.endsWith('.webp') ? 'image/webp' : 'image/jpeg');
    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': 'private, max-age=86400, immutable'
    });
    fs.createReadStream(safeFilePath).pipe(res);
    return;
  }

  // 6. Admin: CSV-Export (GET /admin/export.csv)
  if (req.method === 'GET' && pathname === '/admin/export.csv') {
    if (!isAuthenticated(req)) {
      res.writeHead(302, { 'Location': '/admin' });
      return res.end();
    }

    const entries = [];
    try {
      const folders = fs.readdirSync(SUBMISSIONS_DIR);
      for (const folder of folders) {
        const jsonPath = path.join(SUBMISSIONS_DIR, folder, 'submission.json');
        if (fs.existsSync(jsonPath)) {
          const item = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
          entries.push(item);
        }
      }
    } catch (e) {}

    entries.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));

    let csv = '\uFEFFDatum;Code;Buddy 1;Buddy 2;Gruppe;Punkte;Fotos;Feedback\n';
    entries.forEach(e => {
      const date = new Date(e.submittedAt).toLocaleString('de-DE');
      const b1 = (e.names && e.names[0]) || '';
      const b2 = (e.names && e.names[1]) || '';
      const grp = (e.names && e.names[2]) || '';
      const fb = (e.feedback || '').replace(/[\r\n]+/g, ' ').replace(/"/g, '""');
      csv += `"${date}";"${e.code}";"${b1}";"${b2}";"${grp}";"${e.score || ''}";"${e.photoCount || 0}";"${fb}"\n`;
    });

    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="esn_bingo_einreichungen.csv"'
    });
    return res.end(csv);
  }

  // 7. Admin Dashboard (GET /admin)
  if (req.method === 'GET' && pathname === '/admin') {
    if (!isAuthenticated(req)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(renderLoginForm());
    }

    const submissions = [];
    try {
      const folders = fs.readdirSync(SUBMISSIONS_DIR);
      for (const folder of folders) {
        const jsonPath = path.join(SUBMISSIONS_DIR, folder, 'submission.json');
        if (fs.existsSync(jsonPath)) {
          const item = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
          item.folder = folder;
          submissions.push(item);
        }
      }
    } catch (e) {
      console.error(e);
    }

    submissions.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));

    let html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESN Göttingen — Bingo Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --cyan: #00AEEF; --magenta: #EC008C; --green: #7AC143; --navy: #2E3192;
      --bg: #F4F6FB; --card: #FFFFFF; --text: #141733; --border: #D8DFEE;
      --font-display: "Barlow Condensed", sans-serif;
      --font-body: "Inter", sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--font-body); padding: 24px 16px; }
    .container { max-width: 1100px; margin: 0 auto; }
    header { background: var(--navy); color: #fff; padding: 20px 24px; border-radius: 8px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px; }
    h1 { font-family: var(--font-display); font-size: 32px; letter-spacing: 0.05em; text-transform: uppercase; }
    .stats { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .badge { background: var(--magenta); color: #fff; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 14px; }
    .btn { background: #fff; color: var(--navy); text-decoration: none; padding: 8px 14px; border-radius: 4px; font-weight: 600; font-size: 13px; text-transform: uppercase; font-family: var(--font-display); letter-spacing: 0.05em; border: none; cursor: pointer; display: inline-flex; align-items: center; }
    .btn:hover { background: #e0e6f5; }
    .btn-logout { background: rgba(255,255,255,0.15); color: #fff; }
    .btn-logout:hover { background: rgba(255,255,255,0.3); }
    .cards { display: flex; flex-direction: column; gap: 20px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.04); }
    .card-head { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 14px; }
    .team-name { font-size: 20px; font-weight: 700; color: var(--navy); }
    .meta { font-size: 13px; color: #64748b; margin-top: 3px; }
    .score-box { background: var(--cyan); color: #fff; padding: 6px 14px; border-radius: 6px; font-family: var(--font-display); font-size: 22px; font-weight: 700; }
    .feedback-box { background: #FFF9E6; border-left: 4px solid #F47B20; padding: 10px 14px; font-size: 14px; margin-bottom: 14px; border-radius: 0 4px 4px 0; }
    details { margin-bottom: 14px; }
    summary { cursor: pointer; font-weight: 600; color: var(--navy); font-size: 13.5px; }
    pre { background: #F8FAFC; border: 1px solid var(--border); padding: 12px; border-radius: 4px; font-size: 12px; margin-top: 8px; white-space: pre-wrap; font-family: monospace; }
    .gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; margin-top: 14px; }
    .photo-thumb { position: relative; border-radius: 6px; overflow: hidden; border: 1px solid var(--border); aspect-ratio: 1; background: #eee; }
    .photo-thumb img { width: 100%; height: 100%; object-fit: cover; display: block; transition: transform 0.2s; }
    .photo-thumb:hover img { transform: scale(1.04); }
    .photo-tag { position: absolute; bottom: 0; left: 0; right: 0; background: rgba(20,23,51,0.85); color: #fff; font-size: 10px; padding: 3px 6px; text-align: center; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .empty { text-align: center; padding: 48px 16px; color: #64748b; font-size: 16px; background: #fff; border-radius: 8px; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>ESN Göttingen — Bingo Admin</h1>
      <p style="font-size: 13px; opacity: 0.85;">Angemeldet als <b>${escapeHtml(ADMIN_USER)}</b></p>
    </div>
    <div class="stats">
      <span class="badge">${submissions.length} Einreichung${submissions.length === 1 ? '' : 'en'}</span>
      <a href="/admin/export.csv" class="btn">📥 Excel Export</a>
      <a href="/" target="_blank" class="btn">🌐 Bingo-Karte</a>
      <a href="/admin/logout" class="btn btn-logout">Abmelden</a>
    </div>
  </header>

  <div class="cards">`;

    if (submissions.length === 0) {
      html += `<div class="empty">Es sind noch keine Einreichungen vorhanden. Sobald Teams ihre Karte absenden, erscheinen sie hier.</div>`;
    } else {
      submissions.forEach(sub => {
        const names = sub.names || [];
        const b1 = escapeHtml(names[0] || 'Unbekannt');
        const b2 = escapeHtml(names[1] || 'Unbekannt');
        const grp = names[2] ? ` · Gruppe: ${escapeHtml(names[2])}` : '';
        const dateFormatted = new Date(sub.submittedAt).toLocaleString('de-DE', {
          day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'
        });

        html += `
        <div class="card">
          <div class="card-head">
            <div>
              <div class="team-name">${b1} &amp; ${b2}${grp}</div>
              <div class="meta">Code: <b>${escapeHtml(sub.code)}</b> · Eingereicht am: ${dateFormatted} · ${sub.photoCount || 0} Fotos</div>
            </div>
            <div class="score-box">${escapeHtml(sub.score || '—')} Pkt.</div>
          </div>`;

        if (sub.feedback) {
          html += `<div class="feedback-box"><b>Feedback:</b> ${escapeHtml(sub.feedback)}</div>`;
        }

        if (sub.tasks || sub.events) {
          html += `
          <details>
            <summary>Erledigte Aufgaben &amp; Events anzeigen</summary>
            <pre>${escapeHtml((sub.tasks || '') + '\n\n' + (sub.events ? '--- ESN Events ---\n' + sub.events : ''))}</pre>
          </details>`;
        }

        const photoKeys = Object.keys(sub.photoFiles || {});
        if (photoKeys.length > 0) {
          html += `<div style="font-size:12px; font-weight:700; text-transform:uppercase; color:#64748b; margin-top:8px;">Beweisfotos (${photoKeys.length}):</div>`;
          html += `<div class="gallery">`;
          photoKeys.forEach(key => {
            const fileName = sub.photoFiles[key];
            const safeFolder = encodeURIComponent(sub.folder);
            const safeFile = encodeURIComponent(fileName);
            const photoUrl = `/admin/photo/${safeFolder}/${safeFile}`;
            html += `
            <a href="${photoUrl}" target="_blank" class="photo-thumb">
              <img src="${photoUrl}" loading="lazy" alt="Foto ${escapeHtml(key)}">
              <div class="photo-tag">Feld ${escapeHtml(key)}</div>
            </a>`;
          });
          html += `</div>`;
        }

        html += `</div>`;
      });
    }

    html += `
  </div>
</div>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // 8. API: Einreichung speichern (POST /api/submit)
  if (req.method === 'POST' && pathname === '/api/submit') {
    let body = [];
    let size = 0;
    const MAX_SIZE = 45 * 1024 * 1024; // 45 MB

    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_SIZE) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Upload zu groß (maximal 45MB)' }));
        req.destroy();
        return;
      }
      body.push(chunk);
    });

    req.on('end', () => {
      try {
        const raw = Buffer.concat(body).toString('utf-8');
        const data = JSON.parse(raw);

        const code = String(data.code || 'GOE-XXXX').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 16);
        const names = Array.isArray(data.names) ? data.names.slice(0, 3).map(n => String(n || '').slice(0, 50)) : [];
        const b1 = (names[0] || 'buddy1').trim();
        const b2 = (names[1] || 'buddy2').trim();
        const teamSlug = `${b1}_${b2}`.toLowerCase().replace(/[^a-z0-9_-]/g, '_').slice(0, 40);

        const now = new Date();
        const dateStr = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const folderName = `${dateStr}_${code}_${teamSlug}`;

        const safeFolderName = path.basename(folderName).replace(/[^a-zA-Z0-9_-]/g, '_');
        const folderPath = path.resolve(SUBMISSIONS_DIR, safeFolderName);

        if (!folderPath.startsWith(path.resolve(SUBMISSIONS_DIR))) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Ungültiger Pfad' }));
        }

        fs.mkdirSync(folderPath, { recursive: true });

        const photoFiles = {};
        const photos = typeof data.photos === 'object' && data.photos !== null ? data.photos : {};
        let savedPhotoCount = 0;

        for (const [key, dataUrl] of Object.entries(photos)) {
          if (typeof dataUrl === 'string' && dataUrl.startsWith('data:image/')) {
            const matches = dataUrl.match(/^data:image\/[a-zA-Z0-9+]+;base64,(.+)$/);
            if (matches) {
              const imgBuffer = Buffer.from(matches[1], 'base64');
              const realExt = detectImageFormat(imgBuffer);

              if (realExt) {
                const safeKey = key.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 10);
                const fileName = `foto_${safeKey}.${realExt}`;
                const filePath = path.join(folderPath, fileName);
                fs.writeFileSync(filePath, imgBuffer);
                photoFiles[key] = fileName;
                savedPhotoCount++;
              }
            }
          }
        }

        const meta = {
          code: code,
          names: names,
          score: String(data.score || '').slice(0, 20),
          maxScore: Number(data.maxScore) || 68,
          tasks: String(data.tasks || '').slice(0, 10000),
          events: String(data.events || '').slice(0, 5000),
          feedback: String(data.feedback || '').slice(0, 3000),
          submittedAt: now.toISOString(),
          ip: clientIp,
          photoCount: savedPhotoCount,
          photoFiles: photoFiles
        };

        fs.writeFileSync(path.join(folderPath, 'submission.json'), JSON.stringify(meta, null, 2), 'utf-8');

        console.log(`[INFO] Neue Einreichung erhalten: Code ${code} von Team ${b1} & ${b2} (${savedPhotoCount} Fotos)`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, code: code, photosSaved: savedPhotoCount }));
      } catch (err) {
        console.error('[ERROR] Fehler beim Verarbeiten der Einreichung:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Serverfehler beim Verarbeiten der Einreichung.' }));
      }
    });
    return;
  }

  // 404 für alles andere
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('404 Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[START] ESN Bingo Server läuft auf Port ${PORT}`);
  console.log(`[START] Admin-Bereich: http://localhost:${PORT}/admin`);
});
