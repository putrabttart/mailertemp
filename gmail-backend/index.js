require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ========== CONFIG ADMIN & DATA STORAGE ==========
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'dev-admin-key';

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// Token tetap di root project, seperti versi awal
const TOKEN_PATH = path.join(__dirname, 'token.json');

const ALIASES_PATH = path.join(DATA_DIR, 'aliases.json');
const DOMAINS_PATH = path.join(DATA_DIR, 'domains.json');
const LOGS_PATH = path.join(DATA_DIR, 'logs.json');

// ---------- Helpers JSON ----------
function loadJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    console.error(`Failed to parse ${file}`, e);
    return fallback;
  }
}

function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- Aliases helpers ----------
function loadAliases() {
  return loadJson(ALIASES_PATH, []);
}

function saveAliases(list) {
  saveJson(ALIASES_PATH, list);
}

// ---------- Domains helpers ----------
function loadDomains() {
  const domains = loadJson(DOMAINS_PATH, []);
  return domains;
}

function saveDomains(list) {
  saveJson(DOMAINS_PATH, list);
}

// Ensure at least one default domain
function ensureDefaultDomain() {
  let domains = loadDomains();
  if (!domains.length) {
    const now = new Date().toISOString();
    domains.push({
      name: 'selebungms.my.id',
      active: true,
      createdAt: now
    });
    saveDomains(domains);
  }
}
ensureDefaultDomain();

// ---------- Logs helpers ----------
function loadLogs() {
  return loadJson(LOGS_PATH, []);
}

function saveLogs(list) {
  saveJson(LOGS_PATH, list);
}

function touchLogs(msgs, alias) {
  if (!msgs || !msgs.length) return;
  let logs = loadLogs();
  const indexById = new Map();
  logs.forEach((l, i) => indexById.set(l.id, i));
  const now = new Date().toISOString();

  msgs.forEach(m => {
    const idx = indexById.get(m.id);
    if (idx != null) {
      logs[idx].lastSeenAt = now;
      logs[idx].alias = alias || logs[idx].alias || null;
    } else {
      logs.push({
        id: m.id,
        alias: alias || null,
        from: m.from || '',
        subject: m.subject || '',
        date: m.date || '',
        snippet: m.snippet || '',
        lastSeenAt: now
      });
    }
  });

  saveLogs(logs);
}

// ---------- Admin middleware ----------
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ========== GMAIL OAUTH CLIENT ==========
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Load token dari file kalau ada
if (fs.existsSync(TOKEN_PATH)) {
  try {
    const saved = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
    oauth2Client.setCredentials(saved);
    console.log('Loaded saved token from token.json');
  } catch (e) {
    console.error('Failed to parse token.json', e);
  }
}

// Simpan token
function saveToken(tokens) {
  saveJson(TOKEN_PATH, tokens);
  console.log('Token saved to token.json');
}

// Jika Google refresh token otomatis
oauth2Client.on('tokens', (tokens) => {
  let current = {};
  if (fs.existsSync(TOKEN_PATH)) {
    try {
      current = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
    } catch (e) {
      console.error('Failed to read token.json on refresh', e);
    }
  }
  const updated = { ...current, ...tokens };
  saveToken(updated);
});

// ================= AUTH URL ================
app.get('/auth/url', (req, res) => {
  const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent'
  });

  res.json({ url });
});

app.get('/login', (req, res) => {
  const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent'
  });

  res.redirect(url);
});

// ================= OAUTH CALLBACK ================
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;

  if (!code) return res.status(400).send('No code provided');

  try {
    const { tokens } = await oauth2Client.getToken(code);

    oauth2Client.setCredentials(tokens);
    saveToken(tokens);

    res.send('Auth berhasil! Anda bisa menutup tab ini.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to get tokens');
  }
});

// ================= MIDDLEWARE CEK LOGIN ==================
function requireAuth(req, res, next) {
  if (!fs.existsSync(TOKEN_PATH)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
    oauth2Client.setCredentials(tokens);
    next();
  } catch (e) {
    console.error('Failed to read token.json in requireAuth', e);
    return res.status(500).json({ error: 'Token file invalid' });
  }
}

// ================= GET LIST EMAIL (USER) ==================
app.get('/api/messages', requireAuth, async (req, res) => {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Ambil alias dari query, misal ?alias=nama@selebungms.my.id
    const alias = (req.query.alias || '').trim();

    const listOptions = {
      userId: 'me',
      maxResults: 20,
      labelIds: ['INBOX'],
    };

    // Kalau ada alias, pakai sebagai filter pencarian Gmail
    if (alias) {
      listOptions.q = `to:${alias}`;

      // Update statistik alias (jika sudah terdaftar)
      const now = new Date().toISOString();
      let aliases = loadAliases();
      const found = aliases.find(a => a.address === alias.toLowerCase());
      if (found) {
        found.lastUsedAt = now;
        found.hits = (found.hits || 0) + 1;
        saveAliases(aliases);
      }
    }

    const listRes = await gmail.users.messages.list(listOptions);
    const messages = listRes.data.messages || [];
    const results = [];

    for (const msg of messages) {
      const msgRes = await gmail.users.messages.get({
        userId: 'me',
        id: msg.id,
        format: 'metadata',
        metadataHeaders: ['Subject', 'From', 'Date', 'To']
      });

      const headers = msgRes.data.payload.headers || [];

      const getHeader = (name) =>
        headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';

      results.push({
        id: msg.id,
        subject: getHeader('Subject'),
        from: getHeader('From'),
        to: getHeader('To'),
        date: getHeader('Date'),
        snippet: msgRes.data.snippet || ''
      });
    }

    // simpan ke log untuk live monitor
    touchLogs(results, alias || null);

    res.json({ messages: results });
  } catch (err) {
    console.error('Error fetching messages', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// ================= GET DETAIL EMAIL (USER) ==================
function decodeBase64Url(str = '') {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function extractBody(payload) {
  let bodyHtml = '';
  let bodyText = '';

  function traverse(part) {
    if (!part) return;

    const data = part.body?.data ? decodeBase64Url(part.body.data) : '';

    if (part.mimeType === 'text/html') bodyHtml += data;
    if (part.mimeType === 'text/plain') bodyText += data;

    if (part.parts) part.parts.forEach(traverse);
  }

  traverse(payload);
  return { bodyHtml, bodyText };
}

app.get('/api/messages/:id', requireAuth, async (req, res) => {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const msgRes = await gmail.users.messages.get({
      userId: 'me',
      id: req.params.id,
      format: 'full'
    });

    const headers = msgRes.data.payload.headers || [];

    function getHeader(name) {
      return headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';
    }

    const { bodyHtml, bodyText } = extractBody(msgRes.data.payload);

    res.json({
      id: req.params.id,
      subject: getHeader('Subject'),
      from: getHeader('From'),
      date: getHeader('Date'),
      snippet: msgRes.data.snippet,
      bodyHtml,
      bodyText
    });
  } catch (err) {
    console.error('Error fetching message detail', err);
    res.status(500).json({ error: 'Failed to fetch message detail' });
  }
});

// ================= ALIAS REGISTER (USER SIDE) ==================
app.post('/api/aliases', (req, res) => {
  const address = (req.body.address || '').trim().toLowerCase();
  if (!address || !address.includes('@')) {
    return res.status(400).json({ error: 'Invalid address' });
  }

  const now = new Date().toISOString();
  let aliases = loadAliases();
  const existing = aliases.find(a => a.address === address);

  if (existing) {
    existing.lastUsedAt = now;
    existing.hits = (existing.hits || 0) + 1;
  } else {
    aliases.push({
      address,
      createdAt: now,
      lastUsedAt: now,
      hits: 1,
      active: true
    });
  }

  saveAliases(aliases);
  res.json({ ok: true });
});

// ================= ADMIN API: STATS ==================
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const aliases = loadAliases();
  const domains = loadDomains();
  const total = aliases.length;
  const totalHits = aliases.reduce((sum, a) => sum + (a.hits || 0), 0);

  res.json({
    totalAliases: total,
    totalHits,
    lastAliasCreatedAt: aliases[total - 1]?.createdAt || null,
    totalDomains: domains.length
  });
});

// ================= ADMIN API: ALIASES ==================
app.get('/api/admin/aliases', requireAdmin, (req, res) => {
  const aliases = loadAliases();
  res.json({ aliases });
});

app.delete('/api/admin/aliases/:address', requireAdmin, (req, res) => {
  const addrParam = decodeURIComponent(req.params.address).toLowerCase();
  let aliases = loadAliases();
  const before = aliases.length;
  aliases = aliases.filter(a => a.address !== addrParam);
  saveAliases(aliases);
  res.json({ removed: before - aliases.length });
});

// ================= ADMIN API: DOMAINS ==================
app.get('/api/admin/domains', requireAdmin, (req, res) => {
  const domains = loadDomains();
  res.json({ domains });
});

app.post('/api/admin/domains', requireAdmin, (req, res) => {
  const name = (req.body.name || '').trim().toLowerCase();
  if (!name || !name.includes('.')) {
    return res.status(400).json({ error: 'Invalid domain name' });
  }
  let domains = loadDomains();
  if (domains.find(d => d.name === name)) {
    return res.status(400).json({ error: 'Domain already exists' });
  }
  const now = new Date().toISOString();
  domains.push({
    name,
    active: true,
    createdAt: now
  });
  saveDomains(domains);
  res.json({ ok: true });
});

app.put('/api/admin/domains/:name', requireAdmin, (req, res) => {
  const nameParam = decodeURIComponent(req.params.name).toLowerCase();
  let domains = loadDomains();
  const d = domains.find(d => d.name === nameParam);
  if (!d) return res.status(404).json({ error: 'Domain not found' });

  if (typeof req.body.active === 'boolean') {
    d.active = req.body.active;
  }
  saveDomains(domains);
  res.json({ ok: true, domain: d });
});

app.delete('/api/admin/domains/:name', requireAdmin, (req, res) => {
  const nameParam = decodeURIComponent(req.params.name).toLowerCase();
  let domains = loadDomains();
  const before = domains.length;
  domains = domains.filter(d => d.name !== nameParam);
  saveDomains(domains);
  res.json({ removed: before - domains.length });
});

// ================= ADMIN API: LOGS (LIVE MONITOR) ==================
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const limit = parseInt(req.query.limit || '50', 10);
  const aliasFilter = (req.query.alias || '').toLowerCase().trim();
  let logs = loadLogs();

  if (aliasFilter) {
    logs = logs.filter(l => (l.alias || '').toLowerCase() === aliasFilter);
  }

  logs.sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
  logs = logs.slice(0, limit);

  res.json({ logs });
});

app.delete('/api/admin/logs', requireAdmin, (req, res) => {
  saveLogs([]);
  res.json({ cleared: true });
});

// ================= SERVER START ==================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
