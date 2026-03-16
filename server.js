import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import { Server as TusServer } from '@tus/server';
import { FileStore } from '@tus/file-store';

const PORT = parseInt(process.env.PORT || '3000', 10);
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/tmp/uploads';
const UPLOAD_SECRET = process.env.UPLOAD_SECRET;
const BUNNY_STORAGE_ZONE = process.env.BUNNY_STORAGE_ZONE;
const BUNNY_STORAGE_PASSWORD = process.env.BUNNY_STORAGE_PASSWORD;
const BUNNY_STORAGE_HOSTNAME = process.env.BUNNY_STORAGE_HOSTNAME || 'storage.bunnycdn.com';
const BUNNY_CDN_HOSTNAME = process.env.BUNNY_CDN_HOSTNAME;
const JARVIS_CALLBACK_URL = process.env.JARVIS_CALLBACK_URL; // e.g. http://178.156.253.60:7000
const JARVIS_CALLBACK_TOKEN = process.env.JARVIS_CALLBACK_TOKEN;
const ADMIN_KEY = process.env.ADMIN_KEY;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SLACK_USER_TOKEN = process.env.SLACK_USER_TOKEN;

// Ensure upload dir exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ─── Token validation (same HMAC logic as Jarvis dashboard) ────────────
function validateUploadToken(token) {
  if (!token || !UPLOAD_SECRET) return null;
  const dotIdx = token.indexOf('.');
  if (dotIdx === -1) return null;
  const data = token.substring(0, dotIdx);
  const sig = token.substring(dotIdx + 1);
  const expected = crypto.createHmac('sha256', UPLOAD_SECRET).update(data).digest('hex');
  if (expected.length !== sig.length) return null;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(sig, 'utf8'))) return null;
  } catch { return null; }
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Date.now()) return null;
    if (!payload.ch || !payload.list || !payload.item) return null;
    return payload;
  } catch { return null; }
}

// ─── Admin token generation ────────────────────────────────────────────
function generateUploadToken(channelId, listId, itemId, name) {
  const payload = { ch: channelId, list: listId, item: itemId, name, ts: Date.now(), exp: Date.now() + 48 * 60 * 60 * 1000 };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', UPLOAD_SECRET).update(data).digest('hex');
  return data + '.' + sig;
}

function validateAdminKey(req) {
  const url = new URL(req.url, 'http://localhost');
  const key = url.searchParams.get('key') || req.headers['x-admin-key'];
  return key && ADMIN_KEY && key === ADMIN_KEY;
}

// ─── Slack API helper ──────────────────────────────────────────────────
async function slackApi(token, method, body, useForm) {
  let payload, contentType;
  if (useForm) {
    payload = Object.entries(body).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(typeof v === 'object' ? JSON.stringify(v) : v)).join('&');
    contentType = 'application/x-www-form-urlencoded';
  } else {
    payload = JSON.stringify(body);
    contentType = 'application/json; charset=utf-8';
  }
  const res = await fetch('https://slack.com/api/' + method, {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': contentType },
    body: payload,
  });
  return res.json();
}

// ─── Bunny Storage upload (server-to-server) ───────────────────────────
function uploadToBunny(filePath, remotePath, contentType) {
  return new Promise((resolve, reject) => {
    const stat = fs.statSync(filePath);
    const opts = {
      hostname: BUNNY_STORAGE_HOSTNAME,
      path: '/' + BUNNY_STORAGE_ZONE + '/' + remotePath,
      method: 'PUT',
      timeout: 600000,
      headers: {
        'AccessKey': BUNNY_STORAGE_PASSWORD,
        'Content-Type': contentType || 'application/octet-stream',
        'Content-Length': stat.size,
      },
    };
    console.log(`[BUNNY] Uploading ${remotePath} (${formatBytes(stat.size)})...`);
    const req = https.request(opts, (res) => {
      let body = '';
      res.on('data', (c) => body += c);
      res.on('end', () => {
        if (res.statusCode === 201 || res.statusCode === 200) {
          const cdnUrl = 'https://' + BUNNY_CDN_HOSTNAME + '/' + remotePath;
          console.log(`[BUNNY] Success: ${remotePath} → ${cdnUrl}`);
          resolve(cdnUrl);
        } else {
          console.log(`[BUNNY] Error ${res.statusCode}: ${body}`);
          reject(new Error(`Bunny upload failed (${res.statusCode})`));
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('Bunny upload timeout')); });
    req.on('error', reject);
    fs.createReadStream(filePath).pipe(req);
  });
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ─── In-memory upload session tracking ─────────────────────────────────
// Maps TUS upload IDs to { token, payload, originalName, contentType, cdnUrl }
const uploadSessions = new Map();

// Clean up stale sessions older than 24h
setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [id, session] of uploadSessions) {
    if (session.createdAt < cutoff) {
      uploadSessions.delete(id);
      // Try to clean up orphaned files
      try { fs.unlinkSync(path.join(UPLOAD_DIR, id)); } catch {}
      try { fs.unlinkSync(path.join(UPLOAD_DIR, id + '.json')); } catch {}
    }
  }
}, 60 * 60 * 1000);

// ─── TUS Server ────────────────────────────────────────────────────────
const tusServer = new TusServer({
  path: '/tus',
  datastore: new FileStore({ directory: UPLOAD_DIR }),
  maxSize: 5 * 1024 * 1024 * 1024, // 5GB max
  async onUploadCreate(req, res, upload) {
    // Validate token from metadata
    const token = upload.metadata?.token;
    const payload = validateUploadToken(token);
    if (!payload) {
      throw { status_code: 401, body: 'Invalid or expired upload token' };
    }
    // Store session info
    uploadSessions.set(upload.id, {
      token,
      payload,
      originalName: upload.metadata?.filename || 'file',
      contentType: upload.metadata?.filetype || 'application/octet-stream',
      size: upload.size,
      createdAt: Date.now(),
      cdnUrl: null,
    });
    console.log(`[TUS] Upload created: ${upload.id} "${upload.metadata?.filename}" (${formatBytes(upload.size || 0)}) for "${payload.name}"`);
    return res;
  },
  async onUploadFinish(req, res, upload) {
    const session = uploadSessions.get(upload.id);
    if (!session) {
      console.log(`[TUS] Upload finished but no session: ${upload.id}`);
      return res;
    }
    console.log(`[TUS] Upload finished: ${upload.id} "${session.originalName}" — pushing to Bunny...`);

    // Push to Bunny immediately (server-to-server, fast)
    try {
      const safeName = crypto.randomBytes(2).toString('hex') + '_' +
        session.originalName.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 200);
      const remotePath = session.payload.ch + '/' + session.payload.item + '/' + safeName;
      const localPath = path.join(UPLOAD_DIR, upload.id);
      const cdnUrl = await uploadToBunny(localPath, remotePath, session.contentType);
      session.cdnUrl = cdnUrl;
      session.bunnyName = safeName;
      console.log(`[TUS] Bunny push complete for "${session.originalName}" → ${cdnUrl}`);

      // Clean up local file
      try { fs.unlinkSync(localPath); } catch {}
      try { fs.unlinkSync(localPath + '.json'); } catch {} // TUS metadata file
    } catch (err) {
      console.log(`[TUS] Bunny push failed for "${session.originalName}":`, err.message);
      session.bunnyError = err.message;
    }

    return res;
  },
});

// ─── File serving ──────────────────────────────────────────────────────
const APP_DIR = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'));

let uploadPageCache = null;
function getUploadPage() {
  if (!uploadPageCache) uploadPageCache = fs.readFileSync(path.join(APP_DIR, 'upload.html'), 'utf8');
  return uploadPageCache;
}

let adminPageCache = null;
function getAdminPage() {
  if (!adminPageCache) adminPageCache = fs.readFileSync(path.join(APP_DIR, 'admin.html'), 'utf8');
  return adminPageCache;
}

// ─── HTTP Server ───────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Upload-Length, Upload-Offset, Upload-Metadata, Tus-Resumable, X-HTTP-Method-Override');
  res.setHeader('Access-Control-Expose-Headers', 'Upload-Offset, Upload-Length, Tus-Resumable, Location');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Health check
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, uptime: process.uptime() }));
    return;
  }

  // Upload page
  if ((pathname === '/' || pathname === '/upload' || pathname === '/upload/') && req.method === 'GET') {
    try {
      const page = getUploadPage();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(page);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Upload page not found');
    }
    return;
  }

  // Verify token
  if (pathname === '/upload/verify' && req.method === 'GET') {
    const token = url.searchParams.get('t');
    const payload = validateUploadToken(token);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (!payload) {
      res.end(JSON.stringify({ ok: false, error: 'Invalid or expired upload link' }));
    } else {
      res.end(JSON.stringify({ ok: true, name: payload.name, channelId: payload.ch, itemId: payload.item }));
    }
    return;
  }

  // Complete — gather CDN URLs, call Jarvis callback
  if (pathname === '/upload/complete' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 65536) req.destroy(); });
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const token = data.token;
        const payload = validateUploadToken(token);
        if (!payload) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Invalid or expired upload link' }));
          return;
        }
        const uploadIds = data.uploadIds || [];
        if (uploadIds.length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'No uploads provided' }));
          return;
        }

        // Collect CDN URLs from completed uploads
        const files = [];
        const errors = [];
        for (const id of uploadIds) {
          const session = uploadSessions.get(id);
          if (!session) { errors.push(`Unknown upload: ${id}`); continue; }
          if (session.bunnyError) { errors.push(`${session.originalName}: ${session.bunnyError}`); continue; }
          if (!session.cdnUrl) { errors.push(`${session.originalName}: not yet uploaded to CDN`); continue; }
          files.push({ name: session.originalName, url: session.cdnUrl, size: session.size || 0 });
        }

        if (files.length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'No files uploaded to CDN', details: errors }));
          return;
        }

        console.log(`[COMPLETE] ${files.length} files for "${payload.name}" — forwarding to Jarvis...`);

        // Forward to Jarvis dashboard's /upload/complete
        let jarvisOk = false;
        if (JARVIS_CALLBACK_URL) {
          try {
            const callbackBody = JSON.stringify({ token, files });
            const cbUrl = new URL('/upload/complete', JARVIS_CALLBACK_URL);
            const cbRes = await fetch(cbUrl.toString(), {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...(JARVIS_CALLBACK_TOKEN ? { 'Authorization': 'Bearer ' + JARVIS_CALLBACK_TOKEN } : {}),
              },
              body: callbackBody,
            });
            const cbData = await cbRes.json();
            jarvisOk = cbData.ok;
            console.log(`[COMPLETE] Jarvis callback: ok=${cbData.ok}` + (cbData.error ? ` error=${cbData.error}` : ''));
          } catch (err) {
            console.log(`[COMPLETE] Jarvis callback error:`, err.message);
          }
        }

        // Clean up sessions
        for (const id of uploadIds) {
          uploadSessions.delete(id);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, fileCount: files.length, jarvisOk, errors: errors.length > 0 ? errors : undefined }));
      } catch (err) {
        console.log('[COMPLETE] Error:', err.message);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
      }
    });
    return;
  }

  // ─── Admin routes ───────────────────────────────────────────────────
  if (pathname.startsWith('/admin')) {
    if (!validateAdminKey(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid admin key' }));
      return;
    }

    // Admin page
    if ((pathname === '/admin' || pathname === '/admin/') && req.method === 'GET') {
      try {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(getAdminPage());
      } catch { res.writeHead(500); res.end('Admin page not found'); }
      return;
    }

    // List client channels (private channels the bot is in)
    if (pathname === '/admin/channels' && req.method === 'GET') {
      try {
        const result = await slackApi(SLACK_BOT_TOKEN, 'conversations.list', { types: 'private_channel', limit: 200, exclude_archived: true }, true);
        const channels = (result.channels || [])
          .filter(c => c.is_member)
          .map(c => ({ id: c.id, name: c.name }))
          .sort((a, b) => a.name.localeCompare(b.name));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, channels }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return;
    }

    // List Slack lists (files of type "list") in a channel
    if (pathname === '/admin/lists' && req.method === 'GET') {
      const channelId = url.searchParams.get('channel');
      if (!channelId) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Missing channel' })); return; }
      try {
        // Get channel tabs to find lists
        const result = await slackApi(SLACK_USER_TOKEN, 'conversations.tabs', { channel: channelId }, true);
        const lists = (result.tabs || [])
          .filter(t => t.type === 'list')
          .map(t => ({ id: t.data?.file_id, name: t.label || 'List' }));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, lists }));
      } catch (err) {
        // Fallback: search for list files in the channel
        try {
          const result = await slackApi(SLACK_USER_TOKEN, 'files.list', { channel: channelId, types: 'list', count: 20 }, true);
          const lists = (result.files || []).map(f => ({ id: f.id, name: f.title || f.name || 'List' }));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, lists }));
        } catch (err2) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: err2.message }));
        }
      }
      return;
    }

    // List items in a Slack list
    if (pathname === '/admin/items' && req.method === 'GET') {
      const listId = url.searchParams.get('list');
      if (!listId) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Missing list' })); return; }
      try {
        const info = await slackApi(SLACK_USER_TOKEN, 'files.info', { file: listId }, true);
        const schema = info.file?.list_metadata?.schema || [];
        const nameCol = schema.find(c => c.name === 'Name' || c.name === 'Title' || c.type === 'text');

        const items = (info.file?.list_metadata?.items || []).map(item => {
          let name = item.id;
          if (nameCol && item.cells) {
            const cell = item.cells[nameCol.id];
            if (cell) {
              // Extract text from rich_text or plain value
              const rt = cell.rich_text;
              if (rt && rt[0]?.elements?.[0]?.elements?.[0]?.text) {
                name = rt[0].elements[0].elements[0].text;
              } else if (typeof cell.value === 'string') {
                name = cell.value;
              }
            }
          }
          return { id: item.id, name };
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, items, listName: info.file?.title || 'List' }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return;
    }

    // Generate admin upload token
    if (pathname === '/admin/token' && req.method === 'GET') {
      const ch = url.searchParams.get('channel');
      const list = url.searchParams.get('list');
      const item = url.searchParams.get('item');
      const name = url.searchParams.get('name') || 'Admin Upload';
      if (!ch || !list || !item) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing channel, list, or item' }));
        return;
      }
      const token = generateUploadToken(ch, list, item, name);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, token }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
    return;
  }

  // TUS endpoint — handles /tus and /tus/*
  if (pathname.startsWith('/tus')) {
    return tusServer.handle(req, res);
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

// No timeouts — uploads can take as long as they need
server.timeout = 0;
server.headersTimeout = 0;
server.requestTimeout = 0;
server.keepAliveTimeout = 65000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Upload service listening on port ${PORT}`);
  console.log(`Bunny zone: ${BUNNY_STORAGE_ZONE}, CDN: ${BUNNY_CDN_HOSTNAME}`);
  console.log(`Jarvis callback: ${JARVIS_CALLBACK_URL || 'not configured'}`);
});
