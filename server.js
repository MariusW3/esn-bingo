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
const ADMIN_USER = (process.env.ADMIN_USER || 'admin').trim();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();

// Verzeichnis für Einreichungen anlegen
fs.mkdirSync(SUBMISSIONS_DIR, { recursive: true });

// Sicherheitscheck beim Serverstart: Wurde ein Passwort vergeben?
if (!ADMIN_PASSWORD) {
  console.error('\n' + '='.repeat(70));
  console.error('⛔ ACHTUNG: Die Umgebungsvariable ADMIN_PASSWORD ist NICHT gesetzt!');
  console.error('⛔ Der Zugriff auf den Admin-Bereich und alle Fotos ist gesperrt.');
  console.error('⛔ Bitte setze in Portainer: ADMIN_PASSWORD=<DeinSicheresPasswort>');
  console.error('='.repeat(70) + '\n');
} else if (ADMIN_PASSWORD.length < 8) {
  console.warn('\n⚠️  HINWEIS: Dein ADMIN_PASSWORD ist kürzer als 8 Zeichen. Empfohlen sind mind. 12 Zeichen!\n');
}

// ============================================================================
// SICHERHEITS-HELPER & RATE-LIMITING
// ============================================================================

// Globaler Header-Schutz (XSS, Clickjacking, MIME-Sniffing)
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

// Client-IP ermitteln (auch hinter Nginx Proxy Manager)
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// Timing-Safe-String-Vergleich gegen Timing-Attacks
function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    // Verhindert Längen-Leaks
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Brute-Force-Schutz für den Admin-Login
// 5 Fehlversuche -> IP für 15 Minuten gesperrt
const failedLoginAttempts = new Map(); // ip -> { count, lockedUntil }

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
    entry.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 Minuten Sperre
    console.warn(`[SECURITY] IP ${ip} wurde für 15 Minuten gesperrt (5 Fehlversuche bei Admin-Login).`);
  }
  failedLoginAttempts.set(ip, entry);
}

function resetFailedLogin(ip) {
  failedLoginAttempts.delete(ip);
}

// Rate Limiting für Einreichungen (max 10 pro IP in 10 Minuten)
const submissionRateLimits = new Map();
function checkSubmissionRateLimit(ip) {
  const now = Date.now();
  const entry = submissionRateLimits.get(ip) || { count: 0, resetAt: now + 10 * 60 * 1000 };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + 10 * 60 * 1000;
  }
  entry.count++;
  submissionRateLimits.set(ip, entry);
  return entry.count <= 10;
}

// Basic Authentication Prüfung
function checkBasicAuth(req, res) {
  const ip = getClientIp(req);

  if (!ADMIN_PASSWORD) {
    res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Admin-Bereich ist gesperrt: Bitte setze die Umgebungsvariable ADMIN_PASSWORD in Portainer.');
    return false;
  }

  if (isIpLocked(ip)) {
    const entry = failedLoginAttempts.get(ip);
    const remainingMin = Math.ceil((entry.lockedUntil - Date.now()) / 60000);
    res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`Zu viele Fehlversuche. Diese IP-Adresse ist noch für ${remainingMin} Minute(n) gesperrt.`);
    return false;
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.writeHead(401, {
      'WWW-Authenticate': 'Basic realm="ESN Göttingen Bingo Admin"',
      'Content-Type': 'text/plain; charset=utf-8'
    });
    res.end('Zugriff verweigert: Bitte mit Benutzername und Passwort anmelden.');
    return false;
  }

  try {
    const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf-8');
    const colonIdx = credentials.indexOf(':');
    if (colonIdx === -1) throw new Error('Format ungültig');

    const user = credentials.substring(0, colonIdx);
    const pass = credentials.substring(colonIdx + 1);

    const userMatch = timingSafeCompare(user, ADMIN_USER);
    const passMatch = timingSafeCompare(pass, ADMIN_PASSWORD);

    if (userMatch && passMatch) {
      resetFailedLogin(ip);
      return true;
    }
  } catch (err) {}

  recordFailedLogin(ip);
  res.writeHead(401, {
    'WWW-Authenticate': 'Basic realm="ESN Göttingen Bingo Admin"',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Anmeldung fehlgeschlagen: Falscher Benutzername oder falsches Passwort.');
  return false;
}

// XSS-Schutz: HTML Escaping
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Prüfung der Datei-Header (Magic Bytes) zur Erkennung echter Bilddateien
// Verhindert das Einschleusen von Skripten oder schadhaftem Code
function detectImageFormat(buffer) {
  if (!buffer || buffer.length < 8) return null;
  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'jpg';
  }
  // PNG: 89 50 4E 47
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return 'png';
  }
  // WebP: RIFF ... WEBP
  if (buffer.length >= 12 &&
      buffer.toString('ascii', 0, 4) === 'RIFF' &&
      buffer.toString('ascii', 8, 12) === 'WEBP') {
    return 'webp';
  }
  return null;
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

  // 3. API: Einreichung speichern (POST /api/submit)
  if (req.method === 'POST' && pathname === '/api/submit') {
    if (!checkSubmissionRateLimit(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Zu viele Einreichungen von dieser IP. Bitte später erneut versuchen.' }));
    }

    let body = [];
    let size = 0;
    const MAX_SIZE = 45 * 1024 * 1024; // 45 MB Maximalgröße

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

        // Validierung und Bereinigung
        const code = String(data.code || 'GOE-XXXX').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 16);
        const names = Array.isArray(data.names) ? data.names.slice(0, 3).map(n => String(n || '').slice(0, 50)) : [];
        const b1 = (names[0] || 'buddy1').trim();
        const b2 = (names[1] || 'buddy2').trim();
        const teamSlug = `${b1}_${b2}`.toLowerCase().replace(/[^a-z0-9_-]/g, '_').slice(0, 40);

        const now = new Date();
        const dateStr = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const folderName = `${dateStr}_${code}_${teamSlug}`;

        // Path Traversal Absicherung
        const safeFolderName = path.basename(folderName).replace(/[^a-zA-Z0-9_-]/g, '_');
        const folderPath = path.resolve(SUBMISSIONS_DIR, safeFolderName);

        // Sicherstellen, dass der Pfad innerhalb von SUBMISSIONS_DIR bleibt
        if (!folderPath.startsWith(path.resolve(SUBMISSIONS_DIR))) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Ungültiger Pfad' }));
        }

        fs.mkdirSync(folderPath, { recursive: true });

        // Fotos validieren (Magic Bytes Check) und speichern
        const photoFiles = {};
        const photos = typeof data.photos === 'object' && data.photos !== null ? data.photos : {};
        let savedPhotoCount = 0;

        for (const [key, dataUrl] of Object.entries(photos)) {
          if (typeof dataUrl === 'string' && dataUrl.startsWith('data:image/')) {
            const matches = dataUrl.match(/^data:image\/[a-zA-Z0-9+]+;base64,(.+)$/);
            if (matches) {
              const imgBuffer = Buffer.from(matches[1], 'base64');
              const realExt = detectImageFormat(imgBuffer);

              // Nur echte Bilder speichern!
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

        // Metadaten als submission.json speichern
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

  // 4. Admin: Geschütztes Foto abrufen (GET /admin/photo/:folder/:filename)
  // KEIN unberechtigter Zugriff auf Fotos möglich!
  if (req.method === 'GET' && pathname.startsWith('/admin/photo/')) {
    if (!checkBasicAuth(req, res)) return;

    const parts = pathname.replace('/admin/photo/', '').split('/');
    if (parts.length !== 2) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Foto nicht gefunden.');
    }

    const folder = path.basename(parts[0]);
    const file = path.basename(parts[1]);

    // Strikte Whitelist gegen Path Traversal
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

  // 5. Admin: CSV-Export (GET /admin/export.csv)
  if (req.method === 'GET' && pathname === '/admin/export.csv') {
    if (!checkBasicAuth(req, res)) return;

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

  // 6. Admin Dashboard: Übersicht aller Einreichungen (GET /admin)
  if (req.method === 'GET' && pathname === '/admin') {
    if (!checkBasicAuth(req, res)) return;

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
    .stats { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .badge { background: var(--magenta); color: #fff; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 14px; }
    .btn { background: #fff; color: var(--navy); text-decoration: none; padding: 8px 16px; border-radius: 4px; font-weight: 600; font-size: 13px; text-transform: uppercase; font-family: var(--font-display); letter-spacing: 0.05em; }
    .btn:hover { background: #e0e6f5; }
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
      <p style="font-size: 13px; opacity: 0.85;">Sicherer Administrationsbereich</p>
    </div>
    <div class="stats">
      <span class="badge">${submissions.length} Einreichung${submissions.length === 1 ? '' : 'en'}</span>
      <a href="/admin/export.csv" class="btn">📥 Excel / CSV Export</a>
      <a href="/" target="_blank" class="btn">🌐 Zur Bingo-Seite</a>
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

  // 404 für alle anderen Routen
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('404 Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[START] ESN Bingo Server läuft sicher auf Port ${PORT}`);
  console.log(`[START] Admin-Bereich: http://localhost:${PORT}/admin (User: ${ADMIN_USER})`);
});
