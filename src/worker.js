// ============================================================
// MailHub - Full-Featured Email Service on Cloudflare Workers
// Architecture: D1 Database + R2 Storage + Workers Assets
// Features: Mailbox management, Send/Receive, Verification Code
//           Extraction, Telegram Notifications, Auto-create Mailbox,
//           Email Forwarding, Attachments (R2), Dark/Light Theme,
//           Search, Domain Management, Pin/Favorite,
//           Native CF Email Routing Support
// ============================================================

import PostalMime from 'postal-mime';
import { createMimeMessage } from 'mimetext/browser';

// ---- Fetch with timeout (prevent hanging on unresponsive APIs) ----
async function fetchWithTimeout(url, opts = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...opts, signal: controller.signal });
    return resp;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`Request timeout after ${timeoutMs}ms: ${url.substring(0, 80)}`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ---- Auto-detect CF Account ID from API Token ----
async function getCfAccountId(db, cfToken) {
  if (!cfToken) return null;
  // Check cache first
  const cached = await getSetting(db, '_cf_account_id_cache');
  if (cached) return cached;
  // Try /accounts endpoint (requires Account:Read permission)
  try {
    const resp = await fetchWithTimeout('https://api.cloudflare.com/client/v4/accounts?per_page=1', {
      headers: { 'Authorization': `Bearer ${cfToken}` }
    });
    const data = await resp.json();
    const accounts = data.result || [];
    if (accounts.length > 0) {
      const accountId = accounts[0].id;
      await setSetting(db, '_cf_account_id_cache', accountId);
      return accountId;
    }
  } catch (_) { /* token may lack Account:Read — try zones fallback */ }
  // Fallback: /zones endpoint only requires Zone:Read; each zone carries account.id
  try {
    const resp = await fetchWithTimeout('https://api.cloudflare.com/client/v4/zones?per_page=1&status=active', {
      headers: { 'Authorization': `Bearer ${cfToken}` }
    });
    const data = await resp.json();
    const zones = data.result || [];
    if (zones.length > 0 && zones[0].account?.id) {
      const accountId = zones[0].account.id;
      await setSetting(db, '_cf_account_id_cache', accountId);
      return accountId;
    }
  } catch (_) { /* ignore */ }
  return null;
}

// ---- Database Initialization ----
async function initDB(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS mailboxes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      address TEXT NOT NULL UNIQUE,
      local_part TEXT NOT NULL,
      domain TEXT NOT NULL,
      is_auto_created INTEGER DEFAULT 0,
      is_pinned INTEGER DEFAULT 0,
      is_favorite INTEGER DEFAULT 0,
      forward_to TEXT DEFAULT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mailbox_id INTEGER NOT NULL,
      sender TEXT NOT NULL,
      to_addr TEXT NOT NULL DEFAULT '',
      subject TEXT NOT NULL DEFAULT '',
      preview TEXT DEFAULT '',
      html_content TEXT DEFAULT '',
      text_content TEXT DEFAULT '',
      verification_code TEXT DEFAULT NULL,
      eml_r2_key TEXT DEFAULT '',
      is_read INTEGER DEFAULT 0,
      is_deleted INTEGER DEFAULT 0,
      deleted_at TEXT DEFAULT NULL,
      is_favorite INTEGER DEFAULT 0,
      received_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT DEFAULT '',
      size INTEGER DEFAULT 0,
      r2_key TEXT DEFAULT '',
      content TEXT DEFAULT '',
      FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS sent_emails (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_addr TEXT NOT NULL,
      from_name TEXT DEFAULT '',
      to_addrs TEXT NOT NULL,
      cc_addrs TEXT DEFAULT '',
      bcc_addrs TEXT DEFAULT '',
      subject TEXT NOT NULL DEFAULT '',
      html_content TEXT DEFAULT '',
      text_content TEXT DEFAULT '',
      resend_id TEXT DEFAULT '',
      send_provider TEXT DEFAULT 'resend',
      status TEXT DEFAULT 'sent',
      is_deleted INTEGER DEFAULT 0,
      deleted_at TEXT DEFAULT NULL,
      status_updated_at TEXT DEFAULT NULL,
      delivery_error TEXT DEFAULT NULL,
      is_favorite INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mailboxes_address ON mailboxes(address);
    CREATE INDEX IF NOT EXISTS idx_mailboxes_domain ON mailboxes(domain);
    CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
    CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments(message_id);
    CREATE INDEX IF NOT EXISTS idx_sent_emails_from ON sent_emails(from_addr);
    CREATE INDEX IF NOT EXISTS idx_sent_emails_created ON sent_emails(created_at DESC);
  `);
}

// ---- JWT Helpers ----
async function createJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const exp = Math.floor(Date.now() / 1000) + 7 * 86400;
  const body = btoa(JSON.stringify({ ...payload, exp })).replace(/=/g, '');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  const sigStr = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${header}.${body}.${sigStr}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return null;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ---- Settings Helpers ----
async function getSetting(db, key) {
  const r = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return r ? r.value : null;
}

async function setSetting(db, key, value) {
  await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind(key, value).run();
}

async function getAllSettings(db) {
  const rows = await db.prepare('SELECT key, value FROM settings').all();
  const obj = {};
  for (const r of rows.results) obj[r.key] = r.value;
  return obj;
}

// ---- JWT Secret: env > D1 > auto-generate & persist ----
async function getJwtSecret(db, env) {
  // 1. Use env var if set
  if (env.JWT_SECRET) return env.JWT_SECRET;
  // 2. Check D1 cache
  const stored = await getSetting(db, '_jwt_secret');
  if (stored) return stored;
  // 3. Auto-generate a strong random secret and persist
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const secret = Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
  await setSetting(db, '_jwt_secret', secret);
  return secret;
}

// ---- Verification Code Extraction (3-tier, multi-language) ----
function extractVerificationCode(subject, text) {
  const keywords = [
    'verification', 'verify', 'code', 'confirm', 'otp', 'one-time',
    'passcode', 'pin', 'security code', 'auth', 'login code',
    '验证码', '校验码', '确认码', '动态码', '安全码', '一次性密码',
    '認證碼', '驗證碼',
    '認証コード', '確認コード', '検証コード',
    '인증번호', '확인코드'
  ];

  // Use factory functions to always get a fresh regex with lastIndex=0
  const makeAfterRe  = () => /(?:验证码|校验码|确认码|动态码|code|otp|pin|passcode|verification)[:\s=]*\b([a-z0-9]{4,8})\b/gi;
  // "084711 is your login code" — number must be separated from keyword by non-alphanumeric chars only
  const makeBeforeRe = () => /\b([0-9]{4,8})\b[^a-z0-9]{0,50}(?:verification|verify|code|confirm|otp|passcode|pin|验证码|校验码|确认码|动态码)/gi;
  // Standalone numeric code on its own line or surrounded by whitespace (not mid-sentence digits)
  const makeStandaloneRe = () => /(?:^|[\s:：,，\-])(\d{4,8})(?=$|[\s,，.。\-])/gm;

  const filterCode = (c, context) => {
    if (!c) return false;
    if (/^(19|20)\d{2}$/.test(c)) return false;           // years
    if (/^0+$/.test(c)) return false;                      // all zeros
    if (/^[a-z]+$/i.test(c)) return false;                 // pure letters
    if (/^[0-3]?\d$/.test(c)) return false;               // 1–31 (days/months)
    if (c.length > 8 || c.length < 4) return false;
    // Reject if the number is immediately preceded by '=' (URL param style: token=615960)
    if (context && new RegExp('=["\']?' + c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(context)) return false;
    return true;
  };

  // Strip URLs AND query-param remnants left behind when QP soft-line-breaks cut a URL mid-way
  // e.g. "https://example.com/verify?\nchallenge=615960" → stripUrls removes the https:// part
  // but leaves "challenge=615960"; the second replace catches those remnants.
  const stripUrls = (s) => s ? s
    .replace(/https?:\/\/[^\s<>"']+/gi, ' ')              // full URLs
    .replace(/\b[a-zA-Z_][a-zA-Z0-9_]*=[a-zA-Z0-9_%.+\-]{4,}/g, ' ') // param=value remnants
    : s;

  const cleanText = stripUrls(text);

  // --- Tier 1: subject line ---
  if (subject) {
    const subLower = subject.toLowerCase();
    for (const kw of keywords) {
      if (subLower.includes(kw.toLowerCase())) {
        const codesAfter = [...subject.matchAll(makeAfterRe())].map(m => m[1]).filter(c => filterCode(c, subject));
        if (codesAfter.length) return codesAfter[0];
        const codesBefore = [...subject.matchAll(makeBeforeRe())].map(m => m[1]).filter(c => filterCode(c, subject));
        if (codesBefore.length) return codesBefore[0];
        // Only accept a standalone code from subject if there is exactly one candidate
        const standalones = [...subject.matchAll(makeStandaloneRe())].map(m => m[1]).filter(c => filterCode(c, subject));
        if (standalones.length === 1) return standalones[0];
        break;
      }
    }
  }

  // --- Tier 2: search ALL occurrences of each keyword in the cleaned body ---
  if (cleanText) {
    const textLower = cleanText.toLowerCase();
    for (const kw of keywords) {
      const kwLower = kw.toLowerCase();
      let searchFrom = 0;
      while (true) {
        const idx = textLower.indexOf(kwLower, searchFrom);
        if (idx === -1) break;
        // Region: 40 chars before the keyword, keyword itself, 60 chars after
        const region = cleanText.substring(Math.max(0, idx - 40), idx + kw.length + 60);
        const codesAfter = [...region.matchAll(makeAfterRe())].map(m => m[1]).filter(c => filterCode(c, region));
        if (codesAfter.length) return codesAfter[0];
        const codesBefore = [...region.matchAll(makeBeforeRe())].map(m => m[1]).filter(c => filterCode(c, region));
        if (codesBefore.length) return codesBefore[0];
        searchFrom = idx + 1;
      }
    }
  }

  // --- Tier 3: subject has keyword AND body is very short with exactly one candidate code ---
  if (cleanText && subject) {
    const subLower = subject.toLowerCase();
    const hasKeyword = keywords.some(kw => subLower.includes(kw.toLowerCase()));
    if (hasKeyword) {
      const trimmed = cleanText.trim();
      // Body IS just a code (Railway-style, short OTP emails)
      const pureCode = trimmed.match(/^(\d{4,8})$/);
      if (pureCode && filterCode(pureCode[1], trimmed)) return pureCode[1];
      // Only scan standalone if body is very short (< 120 chars after URL stripping)
      if (trimmed.length <= 120) {
        const standalones = [...trimmed.matchAll(makeStandaloneRe())].map(m => m[1]).filter(c => filterCode(c, trimmed));
        if (standalones.length === 1) return standalones[0];
      }
    }
  }
  return null;
}

// ---- Telegram Notification ----
async function sendTelegramNotification(db, email, verificationCode) {
  const botToken = await getSetting(db, 'tg_bot_token');
  const chatId = await getSetting(db, 'tg_chat_id');
  if (!botToken || !chatId) return;
  const topicId = await getSetting(db, 'tg_topic_id');
  let text = `<b>New Email</b>\n<b>From:</b> ${escapeHtml(email.sender)}\n<b>To:</b> ${escapeHtml(email.to)}\n<b>Subject:</b> ${escapeHtml(email.subject)}`;
  if (verificationCode) text += `\n<b>Code: <code>${verificationCode}</code></b>`;
  const body = { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (topicId) body.message_thread_id = parseInt(topicId);
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
  } catch (e) { console.error('Telegram error:', e); }
}

function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ---- Email Forwarding ----
async function forwardEmail(db, env, email) {
  // Check per-mailbox forwarding first
  let forwardTo = null;
  const mbx = await db.prepare('SELECT forward_to FROM mailboxes WHERE address = ?').bind(email.to).first();
  if (mbx && mbx.forward_to) {
    forwardTo = mbx.forward_to;
  } else {
    forwardTo = await getSetting(db, 'forward_to');
  }
  if (!forwardTo) return;

  const sendMethod = await getSetting(db, 'send_method') || 'auto';
  const resendApiKey = await getSetting(db, 'resend_api_key') || (env && env.RESEND_API_KEY);
  const cfApiToken = await getSetting(db, 'cf_api_token') || (env && env.CF_API_TOKEN_VAR);

  const subject = `[Fwd] ${email.subject || '(no subject)'}`;
  const originalFrom = escapeHtml(email.sender || 'unknown');
  const originalBody = email.html || `<pre>${escapeHtml(email.text || '')}</pre>`;
  const htmlBody = `<p><b>From:</b> ${originalFrom}</p><hr>${originalBody}`;
  // Use the recipient address (your own verified domain) as the from address;
  // the original sender's address cannot be used because mail providers
  // (Resend, CF Email Service) only allow sending from verified domains.
  const fromAddr = email.to || 'noreply@mailhub.local';

  try {
    // Determine forwarding method based on send_method setting
    if (sendMethod === 'resend' && resendApiKey) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${resendApiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: fromAddr, to: [forwardTo], subject, html: htmlBody })
      });
    } else if ((sendMethod === 'cf_email_service' || sendMethod === 'cf_native' || sendMethod === 'auto') && env && env.SEND_EMAIL) {
      // Use CF Email Service binding for forwarding
      try {
        await env.SEND_EMAIL.send({
          from: { email: fromAddr },
          to: [{ email: forwardTo }],
          subject,
          content: [{ type: 'text/html', value: htmlBody }]
        });
      } catch (bindErr) {
        // Fallback to Resend if CF binding fails and Resend key is available
        if (resendApiKey) {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${resendApiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ from: fromAddr, to: [forwardTo], subject, html: htmlBody })
          });
        } else {
          console.error('Forward via CF Email binding failed, no Resend fallback:', bindErr);
        }
      }
    } else if (resendApiKey) {
      // Fallback to Resend for any other case
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${resendApiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: fromAddr, to: [forwardTo], subject, html: htmlBody })
      });
    } else {
      console.error('Forward failed: no sending method available (no Resend API key, no CF Email binding)');
    }
  } catch (e) { console.error('Forward error:', e); }
}

// ---- Generate Preview ----
function generatePreview(html, text, maxLen = 120) {
  const stripTags = (s) => (s || '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // Some senders wrongly put HTML in the text/plain part — detect and strip
  const textTrimmed = (text || '').trimStart();
  const textIsHtml = /^<!doctype\s+html|^<html[\s>]/i.test(textTrimmed);

  let content = textIsHtml ? stripTags(text) : (text || '');

  if (html) {
    const fromHtml = stripTags(html);
    // Prefer HTML-extracted content if: text was actually HTML (already stripped),
    // or text is missing/too short
    if (!content || fromHtml.length > content.length) {
      content = fromHtml;
    }
  }
  return content.substring(0, maxLen);
}

// ---- Main Worker ----
// Track whether DB has been initialized in this isolate
let dbInitialized = false;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const db = env.DB;

    // Auto-init DB (only once per isolate lifetime)
    if (!dbInitialized) {
      // Step 1: Create tables (ignore errors if tables already exist)
      try { await initDB(db); } catch (e) { /* tables may already exist */ }

      // Step 2: Always run migrations independently so columns are never missing
      const migrations = [
        `ALTER TABLE messages ADD COLUMN eml_r2_key TEXT DEFAULT ''`,
        `ALTER TABLE attachments ADD COLUMN r2_key TEXT DEFAULT ''`,
        `ALTER TABLE messages ADD COLUMN is_deleted INTEGER DEFAULT 0`,
        `ALTER TABLE messages ADD COLUMN deleted_at TEXT DEFAULT NULL`,
        `ALTER TABLE messages ADD COLUMN is_favorite INTEGER DEFAULT 0`,
        `ALTER TABLE sent_emails ADD COLUMN is_deleted INTEGER DEFAULT 0`,
        `ALTER TABLE sent_emails ADD COLUMN deleted_at TEXT DEFAULT NULL`,
        `ALTER TABLE sent_emails ADD COLUMN send_provider TEXT DEFAULT 'resend'`,
        `ALTER TABLE sent_emails ADD COLUMN status_updated_at TEXT DEFAULT NULL`,
        `ALTER TABLE sent_emails ADD COLUMN delivery_error TEXT DEFAULT NULL`,
        `ALTER TABLE sent_emails ADD COLUMN is_favorite INTEGER DEFAULT 0`,
      ];
      for (const sql of migrations) {
        try { await db.prepare(sql).run(); } catch (e) { /* column already exists, ignore */ }
      }

      // Step 3: Create supplementary tables and indexes (safe to run multiple times)
      try {
        await db.prepare(`
          CREATE TABLE IF NOT EXISTS sent_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sent_email_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content_type TEXT DEFAULT '',
            size INTEGER DEFAULT 0,
            r2_key TEXT DEFAULT '',
            cid TEXT DEFAULT '',
            FOREIGN KEY (sent_email_id) REFERENCES sent_emails(id) ON DELETE CASCADE
          )
        `).run();
      } catch (e) { /* already exists */ }
      try {
        await db.prepare(`CREATE INDEX IF NOT EXISTS idx_sent_attachments_email ON sent_attachments(sent_email_id)`).run();
      } catch (e) { /* already exists */ }
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_messages_deleted ON messages(is_deleted)`).run().catch(()=>{});
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_sent_deleted ON sent_emails(is_deleted)`).run().catch(()=>{});
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_messages_favorite ON messages(is_favorite)`).run().catch(()=>{});
      // Add cid column for inline image tracking (safe if already exists)
      await db.prepare(`ALTER TABLE sent_attachments ADD COLUMN cid TEXT DEFAULT ''`).run().catch(()=>{});

      dbInitialized = true;
    }
    // CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });

    // Auth helper
    const verifyAuth = async (req) => {
      const auth = req.headers.get('Authorization');
      if (!auth || !auth.startsWith('Bearer ')) return false;
      const token = auth.slice(7);
      const jwtSecret = await getJwtSecret(db, env);
      const payload = await verifyJWT(token, jwtSecret);
      return !!payload;
    };

    try {
      // ---- Public Routes ----
      if (path === '/api/login' && request.method === 'POST') {
        return await handleLogin(request, env, db, json);
      }
      if (path === '/api/webhook/inbound' && request.method === 'POST') {
        return await handleInboundWebhook(request, env, db, json);
      }
      if (path === '/api/resend-events' && request.method === 'POST') {
        return await handleResendDeliveryWebhook(request, db, json);
      }
      if (path === '/api/config') {
        // Get domains based on current provider setting
        let domains = [];
        const domainProvider = await getSetting(db, 'domain_provider') || 'resend';
        const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
        const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;

        if (domainProvider === 'cf' && cfToken) {
          // CF Email Service: get verified sending subdomains
          try {
            const zoneResp = await fetchWithTimeout('https://api.cloudflare.com/client/v4/zones?per_page=50&status=active', {
              headers: { 'Authorization': `Bearer ${cfToken}` }
            }, 10000);
            const zoneData = await zoneResp.json();
            const zones = zoneData.result || [];
            for (const zone of zones) {
              try {
                const subResp = await fetchWithTimeout(
                  `https://api.cloudflare.com/client/v4/zones/${zone.id}/email/sending/subdomains`,
                  { headers: { 'Authorization': `Bearer ${cfToken}` } },
                  5000
                );
                const subData = await subResp.json();
                const subs = subData.result || [];
                for (const sub of subs) {
                  if (sub.enabled) domains.push(sub.name);
                }
              } catch (e) { /* ignore per-zone errors */ }
            }
          } catch (e) { /* ignore */ }
        } else if (resendKey) {
          // Resend: get verified domains
          try {
            const resp = await fetch('https://api.resend.com/domains', {
              headers: { 'Authorization': `Bearer ${resendKey}` }
            });
            const data = await resp.json();
            domains = (data.data || []).filter(d => d.status === 'verified').map(d => d.name);
          } catch (e) { /* ignore */ }
        }
        // Fallback: get unique domains from existing mailboxes
        if (domains.length === 0) {
          try {
            const rows = await db.prepare('SELECT DISTINCT domain FROM mailboxes ORDER BY domain').all();
            domains = (rows.results || []).map(r => r.domain);
          } catch (e) { /* ignore */ }
        }
        // Return Turnstile site key only if both keys are configured (complete setup)
        const turnstileSiteKey = env.TURNSTILE_SITE_KEY || '';
        const turnstileSecretKey = env.TURNSTILE_SECRET_KEY || '';
        return json({ domains, domain_provider: domainProvider, turnstile_site_key: (turnstileSiteKey && turnstileSecretKey) ? turnstileSiteKey : '' });
      }

      // ---- Auth Required ----
      if (path.startsWith('/api/')) {
        if (!await verifyAuth(request)) return json({ error: 'Unauthorized' }, 401);

        // Mailboxes
        if (path === '/api/mailboxes' && request.method === 'GET') return await handleListMailboxes(db, url, json);
        if (path === '/api/mailboxes' && request.method === 'POST') return await handleCreateMailbox(request, db, json);
        if (path.match(/^\/api\/mailboxes\/\d+$/) && request.method === 'DELETE') return await handleDeleteMailbox(path, db, json, env);
        if (path === '/api/mailboxes/pin' && request.method === 'POST') return await handleTogglePin(request, db, json);
        if (path.match(/^\/api\/mailboxes\/\d+\/favorite$/) && request.method === 'POST') return await handleToggleFavorite(path, db, json);
        if (path.match(/^\/api\/mailboxes\/\d+\/forward$/) && request.method === 'POST') return await handleSetForward(request, path, db, json);

        // Messages
        if (path === '/api/messages' && request.method === 'GET') return await handleListMessages(db, url, json);
        if (path.match(/^\/api\/messages\/\d+$/) && request.method === 'GET') return await handleGetMessage(path, db, env, json);
        if (path.match(/^\/api\/messages\/\d+$/) && request.method === 'DELETE') return await handleDeleteMessage(path, db, env, json);
        if (path === '/api/messages/bulk-delete' && request.method === 'POST') return await handleBulkDeleteMessages(request, db, env, json);
        if (path === '/api/messages/search' && request.method === 'GET') return await handleSearchMessages(db, url, json);
        if (path === '/api/messages/clear' && request.method === 'POST') return await handleClearMailboxMessages(request, db, env, json);
        if (path.match(/^\/api\/messages\/\d+\/favorite$/) && request.method === 'POST') return await handleToggleMessageFavorite(path, db, json);
        if (path.match(/^\/api\/messages\/\d+\/eml$/) && request.method === 'GET') return await handleDownloadEml(path, db, env, corsHeaders);
        if (path.match(/^\/api\/messages\/\d+\/read$/) && request.method === 'POST') return await handleMarkRead(path, db, json);
        if (path === '/api/messages/mark-all-read' && request.method === 'POST') return await handleMarkAllRead(request, db, json);

        // Attachments (R2 download)
        if (path.match(/^\/api\/attachments\/\d+\/download$/) && request.method === 'GET') return await handleDownloadAttachment(path, db, env, corsHeaders);
        if (path.match(/^\/api\/sent-attachments\/\d+\/download$/) && request.method === 'GET') return await handleDownloadSentAttachment(path, db, env, corsHeaders);

        // Send
        if (path === '/api/send' && request.method === 'POST') return await handleSendEmail(request, env, db, json);

        // Sent
        if (path === '/api/sent' && request.method === 'GET') return await handleListSent(db, url, json);
        if (path.match(/^\/api\/sent\/\d+$/) && request.method === 'GET') return await handleGetSentEmail(path, db, json);
        if (path.match(/^\/api\/sent\/\d+$/) && request.method === 'DELETE') return await handleDeleteSentEmail(path, db, json);
        if (path.match(/^\/api\/sent\/\d+\/status$/) && request.method === 'GET') return await handleCheckSentStatus(path, db, env, json);
        if (path.match(/^\/api\/sent\/\d+\/favorite$/) && request.method === 'POST') return await handleToggleSentFavorite(path, db, json);

        // Trash (deleted items)
        if (path === '/api/trash' && request.method === 'GET') return await handleListTrash(db, url, json);
        if (path === '/api/trash/restore' && request.method === 'POST') return await handleRestoreFromTrash(request, db, json);
        if (path === '/api/trash/permanent' && request.method === 'POST') return await handlePermanentDelete(request, db, env, json);
        if (path === '/api/trash/clear' && request.method === 'POST') return await handleClearTrash(db, env, json);

        // Domains
        if (path === '/api/domains' && request.method === 'GET') return await handleListDomains(env, db, json);
        if (path === '/api/domains/enable' && request.method === 'POST') return await handleEnableDomain(request, env, db, json);
        if (path === '/api/domains/disable' && request.method === 'POST') return await handleDisableDomain(request, env, db, json);
        if (path === '/api/domains/verify' && request.method === 'POST') return await handleVerifyDomain(request, env, db, json);
        if (path === '/api/domains/dns' && request.method === 'GET') return await handleGetDnsRecords(env, db, url, json);
        if (path === '/api/domains/auto-dns' && request.method === 'POST') return await handleAutoDns(request, env, db, json);
        if (path === '/api/email-routing/setup' && request.method === 'POST') return await handleSetupEmailRouting(request, env, db, json);
        if (path === '/api/email-routing/status' && request.method === 'GET') return await handleEmailRoutingStatus(env, db, url, json);

        // Settings
        if (path === '/api/settings' && request.method === 'GET') return await handleGetSettings(db, env, json);
        if (path === '/api/settings' && request.method === 'PUT') return await handleSaveSettings(request, db, json);

        // Stats
        if (path === '/api/stats' && request.method === 'GET') return await handleGetStats(db, env, json);
        if (path === '/api/unread-count' && request.method === 'GET') return await handleGetUnreadCount(db, json);
        if (path === '/api/folder-counts' && request.method === 'GET') return await handleFolderCounts(db, url, json);

        // Password change
        if (path === '/api/change-password' && request.method === 'POST') return await handleChangePassword(request, env, db, json);

        return json({ error: 'Not found' }, 404);
      }

      // Let Workers Assets handle static files
      return new Response('Not found', { status: 404 });
    } catch (e) {
      console.error('Worker error:', e);
      return json({ error: e.message || 'Internal error' }, 500);
    }
  },

  // ---- Native CF Email Routing Handler ----
  async email(message, env, ctx) {
    const db = env.DB;
    if (!dbInitialized) {
      try { await initDB(db); } catch (e) { /* tables may already exist */ }
      // Ensure sent_attachments table exists (may be missing from older d1-init.sql)
      try {
        await db.prepare(`
          CREATE TABLE IF NOT EXISTS sent_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sent_email_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content_type TEXT DEFAULT '',
            size INTEGER DEFAULT 0,
            r2_key TEXT DEFAULT '',
            cid TEXT DEFAULT '',
            FOREIGN KEY (sent_email_id) REFERENCES sent_emails(id) ON DELETE CASCADE
          )
        `).run();
      } catch (e) { /* already exists */ }
      dbInitialized = true;
    }

    try {
      // Read raw email bytes
      const rawEmail = await new Response(message.raw).arrayBuffer();
      const rawBytes = new Uint8Array(rawEmail);

      // Parse with PostalMime
      const parser = new PostalMime();
      const parsed = await parser.parse(rawEmail);

      // Prefer the From header (parsed.from) over the envelope sender (message.from)
      // message.from is the SMTP envelope sender (Return-Path), often a bounce/VERP address
      // parsed.from is the actual From header that the end user sees
      const parsedFrom = parsed.from?.text || parsed.from?.address || '';
      const sender = parsedFrom || message.from || '';
      const to = message.to || '';
      const subject = parsed.subject || '(no subject)';
      const html = parsed.html || '';
      const text = parsed.text || '';

      // Normalize attachments from PostalMime format
      const attachments = (parsed.attachments || []).map(att => ({
        filename: att.filename || 'attachment',
        content_type: att.mimeType || '',
        size: att.content ? att.content.byteLength || att.content.length : 0,
        content: att.content // Uint8Array from PostalMime
      }));

      await processInboundEmail(db, env, {
        sender, to, subject, html, text, attachments, rawBytes
      });
    } catch (e) {
      console.error('Email handler error:', e);
    }
  }
};

// ============================================================
// API Handlers
// ============================================================

// ---- Auth ----
async function handleLogin(request, env, db, json) {
  const { username, password, turnstile_token, setup_config } = await request.json();

  const dbUsername = await getSetting(db, 'admin_username');
  const dbPassword = await getSetting(db, 'admin_password');
  const envUsername = env.ADMIN_USERNAME;
  const envPassword = env.ADMIN_PASSWORD;

  // First-run setup: no credentials in DB or Env
  // Turnstile is skipped for first-run setup — no account exists yet so there
  // is nothing to brute-force, and the setup form does not render the widget.
  const isFirstRun = !dbUsername && !dbPassword && !envUsername && !envPassword;

  // Verify Turnstile only for normal logins (both keys must be configured)
  if (!isFirstRun) {
    const turnstileSecret = env.TURNSTILE_SECRET_KEY || '';
    const turnstileSiteKey = env.TURNSTILE_SITE_KEY || '';
    if (turnstileSecret && turnstileSiteKey) {
      if (!turnstile_token) return json({ error: 'Please complete the verification' }, 400);
      try {
        const formData = new URLSearchParams();
        formData.append('secret', turnstileSecret);
        formData.append('response', turnstile_token);
        const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
        if (clientIP) formData.append('remoteip', clientIP);
        const verifyResp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: formData.toString()
        });
        const verifyResult = await verifyResp.json();
        if (!verifyResult.success) return json({ error: 'Verification failed' }, 403);
      } catch (e) { return json({ error: 'Verification service error' }, 500); }
    }
  }

  if (isFirstRun) {
    if (!setup_config) return json({ setup_required: true });
    const { new_username, new_password, cf_token, resend_key, domain_provider } = setup_config;
    if (!new_username || !new_password || new_username.length < 2 || new_password.length < 6) {
      return json({ error: 'Invalid setup configuration' }, 400);
    }
    // Validate CF Token before saving
    if (cf_token) {
      const cfValid = await validateCfToken(cf_token);
      if (!cfValid.success) return json({ error: 'CF Token validation failed: ' + cfValid.error }, 400);
    }
    // Validate Resend Key
    if (domain_provider === 'resend' && resend_key) {
      const resendValid = await validateResendKey(resend_key);
      if (!resendValid.success) return json({ error: 'Resend Key validation failed: ' + resendValid.error }, 400);
    }
    await setSetting(db, 'admin_username', new_username);
    await setSetting(db, 'admin_password', new_password);
    if (cf_token) await setSetting(db, 'cf_api_token', cf_token);
    if (resend_key) await setSetting(db, 'resend_api_key', resend_key);
    if (domain_provider) await setSetting(db, 'domain_provider', domain_provider);
    // Derive send_method from domain_provider so the correct backend is used immediately
    const derivedSendMethod = domain_provider === 'resend' ? 'resend' : 'cf_email_service';
    await setSetting(db, 'send_method', derivedSendMethod);
    const token = await createJWT({ role: 'admin', username: new_username }, await getJwtSecret(db, env));
    return json({ token, username: new_username });
  }

  const validUsername = dbUsername || envUsername || 'admin';
  const validPassword = dbPassword || envPassword;
  if (username !== validUsername || password !== validPassword) return json({ error: 'Invalid username or password' }, 401);
  const token = await createJWT({ role: 'admin', username: validUsername }, await getJwtSecret(db, env));
  return json({ token, username: validUsername });
}

async function validateCfToken(token) {
  try {
    const resp = await fetch('https://api.cloudflare.com/client/v4/user/tokens/verify', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await resp.json();
    if (!data.success) return { success: false, error: data.errors?.[0]?.message || 'Invalid token' };
    if (data.result?.status !== 'active') return { success: false, error: 'Token is not active' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
}

async function validateResendKey(key) {
  try {
    const resp = await fetch('https://api.resend.com/api-keys', {
      headers: { 'Authorization': `Bearer ${key}` }
    });
    if (resp.status === 200) return { success: true };
    const data = await resp.json();
    return { success: false, error: data.message || 'Invalid API key' };
  } catch (e) { return { success: false, error: e.message }; }
}

async function handleChangePassword(request, env, db, json) {
  const { current_password, new_password, new_username } = await request.json();
  if (!new_password || new_password.length < 6) return json({ error: 'New password must be at least 6 characters' }, 400);
  const dbPassword = await getSetting(db, 'admin_password');
  const validPassword = dbPassword || env.ADMIN_PASSWORD;
  if (current_password !== validPassword) return json({ error: 'Current password is incorrect' }, 401);
  await setSetting(db, 'admin_password', new_password);
  // Update username if provided
  if (new_username && new_username.trim().length >= 2) {
    await setSetting(db, 'admin_username', new_username.trim());
  }
  return json({ success: true });
}

// ---- Mailboxes ----
async function handleListMailboxes(db, url, json) {
  const domain = url.searchParams.get('domain');
  const search = url.searchParams.get('search');
  let query = 'SELECT m.*, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id AND is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)) as unread_count, (SELECT COUNT(*) FROM messages WHERE mailbox_id = m.id AND (is_deleted = 0 OR is_deleted IS NULL)) as total_count FROM mailboxes m';
  const conditions = [];
  const params = [];
  if (domain) { conditions.push('m.domain = ?'); params.push(domain); }
  if (search) { conditions.push('m.address LIKE ?'); params.push(`%${search}%`); }
  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
  query += ' ORDER BY m.is_pinned DESC, m.is_favorite DESC, m.created_at DESC';
  const stmt = params.length ? db.prepare(query).bind(...params) : db.prepare(query);
  const result = await stmt.all();
  return json({ mailboxes: result.results });
}

async function handleCreateMailbox(request, db, json) {
  const { address, domain, local_part } = await request.json();
  let addr, local, dom;
  if (address) {
    addr = address.toLowerCase().trim();
    const parts = addr.split('@');
    local = parts[0]; dom = parts[1];
  } else if (domain && local_part) {
    local = local_part.toLowerCase().trim();
    dom = domain.toLowerCase().trim();
    addr = `${local}@${dom}`;
  } else {
    return json({ error: 'Domain is required' }, 400);
  }
  try {
    await db.prepare('INSERT INTO mailboxes (address, local_part, domain) VALUES (?, ?, ?)').bind(addr, local, dom).run();
    const mbx = await db.prepare('SELECT * FROM mailboxes WHERE address = ?').bind(addr).first();
    return json({ mailbox: mbx });
  } catch (e) {
    if (e.message?.includes('UNIQUE')) return json({ error: 'Address already exists' }, 409);
    throw e;
  }
}

async function handleDeleteMailbox(path, db, json, env) {
  const id = parseInt(path.split('/').pop());
  // Clean up R2 files for all messages in this mailbox
  try {
    const msgs = await db.prepare('SELECT id FROM messages WHERE mailbox_id = ?').bind(id).all();
    for (const msg of msgs.results) {
      await cleanupMessageR2(db, env, msg.id);
    }
  } catch (e) { /* best-effort cleanup */ }
  await db.prepare('DELETE FROM mailboxes WHERE id = ?').bind(id).run();
  return json({ success: true });
}

async function handleTogglePin(request, db, json) {
  const { id } = await request.json();
  const mbx = await db.prepare('SELECT is_pinned FROM mailboxes WHERE id = ?').bind(id).first();
  if (!mbx) return json({ error: 'Not found' }, 404);
  await db.prepare('UPDATE mailboxes SET is_pinned = ? WHERE id = ?').bind(mbx.is_pinned ? 0 : 1, id).run();
  return json({ success: true, is_pinned: !mbx.is_pinned });
}

async function handleToggleFavorite(path, db, json) {
  const id = parseInt(path.split('/')[3]);
  const mbx = await db.prepare('SELECT is_favorite FROM mailboxes WHERE id = ?').bind(id).first();
  if (!mbx) return json({ error: 'Not found' }, 404);
  await db.prepare('UPDATE mailboxes SET is_favorite = ? WHERE id = ?').bind(mbx.is_favorite ? 0 : 1, id).run();
  return json({ success: true, is_favorite: !mbx.is_favorite });
}

async function handleSetForward(request, path, db, json) {
  const id = parseInt(path.split('/')[3]);
  const { forward_to } = await request.json();
  await db.prepare('UPDATE mailboxes SET forward_to = ? WHERE id = ?').bind(forward_to || null, id).run();
  return json({ success: true });
}

// ---- Messages ----
async function handleListMessages(db, url, json) {
  return handleSearchMessages(db, url, json);
}

async function handleGetMessage(path, db, env, json) {
  const id = parseInt(path.split('/').pop());
  const msg = await db.prepare('SELECT * FROM messages WHERE id = ?').bind(id).first();
  if (!msg) return json({ error: 'Not found' }, 404);
  // Mark as read
  if (!msg.is_read) {
    await db.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').bind(id).run();
  }
  // Get attachments
  const atts = await db.prepare('SELECT id, filename, content_type, size, r2_key FROM attachments WHERE message_id = ?').bind(id).all();
  return json({ message: { ...msg, is_read: 1, has_eml: !!msg.eml_r2_key }, attachments: atts.results });
}

async function handleMarkRead(path, db, json) {
  const id = parseInt(path.split('/')[3]);
  await db.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').bind(id).run();
  return json({ success: true });
}

async function handleMarkAllRead(request, db, json) {
  try {
    const body = await request.json().catch(() => ({}));
    const mailboxId = body.mailbox_id;
    if (mailboxId) {
      await db.prepare('UPDATE messages SET is_read = 1 WHERE mailbox_id = ? AND is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)').bind(mailboxId).run();
    } else {
      await db.prepare('UPDATE messages SET is_read = 1 WHERE is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)').run();
    }
    return json({ success: true });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

async function handleToggleMessageFavorite(path, db, json) {
  const id = parseInt(path.split('/')[3]);
  const msg = await db.prepare('SELECT is_favorite FROM messages WHERE id = ?').bind(id).first();
  if (!msg) return json({ error: 'Not found' }, 404);
  const newVal = msg.is_favorite ? 0 : 1;
  await db.prepare('UPDATE messages SET is_favorite = ? WHERE id = ?').bind(newVal, id).run();
  return json({ success: true, is_favorite: newVal });
}

async function handleDeleteMessage(path, db, env, json) {
  const id = parseInt(path.split('/').pop());
  // Soft delete: move to trash
  await db.prepare('UPDATE messages SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id = ?').bind(id).run();
  return json({ success: true });
}

async function handleBulkDeleteMessages(request, db, env, json) {
  const { ids } = await request.json();
  if (!ids || !ids.length) return json({ error: 'No IDs provided' }, 400);
  // Soft delete: move to trash
  const placeholders = ids.map(() => '?').join(',');
  await db.prepare(`UPDATE messages SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id IN (${placeholders})`).bind(...ids).run();
  return json({ success: true, deleted: ids.length });
}

async function handleSearchMessages(db, url, json) {
  const q = url.searchParams.get('q') || '';
  const mailboxId = url.searchParams.get('mailbox_id');
  const isFavorite = url.searchParams.get('is_favorite');
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = parseInt(url.searchParams.get('limit') || '20');
  const offset = (page - 1) * limit;

  // Check if is_favorite column exists (handles old DBs without migration)
  let hasFavoriteCol = true;
  try {
    await db.prepare('SELECT is_favorite FROM messages LIMIT 0').all();
  } catch (e) {
    hasFavoriteCol = false;
    // Try to add the column now
    try { await db.prepare('ALTER TABLE messages ADD COLUMN is_favorite INTEGER DEFAULT 0').run(); hasFavoriteCol = true; } catch (e2) { /* ignore */ }
  }

  const favSelect = hasFavoriteCol ? ', is_favorite' : ', 0 as is_favorite';
  let query = 'SELECT id, mailbox_id, sender, to_addr, subject, preview, verification_code, is_read' + favSelect + ', received_at FROM messages WHERE (is_deleted = 0 OR is_deleted IS NULL)';
  let countQuery = 'SELECT COUNT(*) as total FROM messages WHERE (is_deleted = 0 OR is_deleted IS NULL)';
  const params = [];
  const countParams = [];

  if (q) {
    query += ' AND (subject LIKE ? OR sender LIKE ? OR preview LIKE ?)';
    countQuery += ' AND (subject LIKE ? OR sender LIKE ? OR preview LIKE ?)';
    const searchTerm = `%${q}%`;
    params.push(searchTerm, searchTerm, searchTerm);
    countParams.push(searchTerm, searchTerm, searchTerm);
  }

  if (mailboxId) {
    query += ' AND mailbox_id = ?';
    countQuery += ' AND mailbox_id = ?';
    params.push(parseInt(mailboxId));
    countParams.push(parseInt(mailboxId));
  }

  if ((isFavorite === '1' || isFavorite === 'true') && hasFavoriteCol) {
    query += ' AND is_favorite = 1';
    countQuery += ' AND is_favorite = 1';
  }
  query += ' ORDER BY received_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const [messages, countResult] = await Promise.all([
    db.prepare(query).bind(...params).all(),
    countParams.length ? db.prepare(countQuery).bind(...countParams).first() : db.prepare(countQuery).first()
  ]);

  return json({
    messages: messages.results,
    total: countResult.total,
    page, limit,
    pages: Math.ceil(countResult.total / limit)
  });
}

async function handleClearMailboxMessages(request, db, env, json) {
  const { mailbox_id } = await request.json();
  if (!mailbox_id) return json({ error: 'mailbox_id required' }, 400);
  // Soft delete: move to trash instead of permanently deleting
  await db.prepare('UPDATE messages SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE mailbox_id = ? AND (is_deleted = 0 OR is_deleted IS NULL)').bind(mailbox_id).run();
  return json({ success: true });
}

// ---- Send Email ----
async function handleSendEmail(request, env, db, json) {
  const body = await request.json();
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;

  // Read preferred send method from settings: 'resend', 'cf_native', 'cf_email_service', or 'auto'
  const preferredMethod = await getSetting(db, 'send_method') || 'auto';
  // CF API token can be used for REST-API email sending even when the SEND_EMAIL binding is absent
  const cfTokenForSend = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
  let sendMethod = null;
  if (preferredMethod === 'resend') {
    if (!resendKey) return json({ error: 'Resend API key not configured' }, 400);
    sendMethod = 'resend';
  } else if (preferredMethod === 'cf_native') {
    if (!env.SEND_EMAIL) return json({ error: 'CF Send Email binding not available' }, 400);
    sendMethod = 'cf_native';
  } else if (preferredMethod === 'cf_email_service') {
    // If the Workers binding is absent, the send path will fall back to CF REST API using cf_api_token.
    // Only hard-fail here if neither the binding nor a token is available.
    if (!env.SEND_EMAIL && !cfTokenForSend) {
      return json({ error: 'CF Email Service not available: SEND_EMAIL binding is not configured and no Cloudflare API token is set. Add a CF API token in Settings.' }, 400);
    }
    sendMethod = 'cf_email_service';
  } else {
    // auto: prefer CF Email Service binding, then CF REST API via token, then Resend
    if (env.SEND_EMAIL || cfTokenForSend) {
      sendMethod = 'cf_email_service';
    } else if (resendKey) {
      sendMethod = 'resend';
    }
  }
  if (!sendMethod) return json({ error: 'No email sending method configured. Add a Resend API key or a Cloudflare API token in Settings.' }, 400);

  const fromAddr = body.from;
  if (!fromAddr) return json({ error: 'Sender address (from) is required' }, 400);
  const toAddrs = Array.isArray(body.to) ? body.to : [body.to];
  if (!toAddrs.length || !toAddrs[0]) return json({ error: 'Recipient address (to) is required' }, 400);
  const subject = body.subject || '(no subject)';
  const htmlContent = body.html || '';
  const textContent = body.text || '';
  const ccAddrs = body.cc ? (Array.isArray(body.cc) ? body.cc : [body.cc]) : [];
  const bccAddrs = body.bcc ? (Array.isArray(body.bcc) ? body.bcc : [body.bcc]) : [];
  const attachments = body.attachments || [];

  // Auto-create mailbox for the sender address if it doesn't exist
  try {
    const existing = await db.prepare('SELECT id FROM mailboxes WHERE address = ?').bind(fromAddr.toLowerCase()).first();
    if (!existing) {
      const parts = fromAddr.toLowerCase().split('@');
      if (parts.length === 2) {
        await db.prepare('INSERT OR IGNORE INTO mailboxes (address, local_part, domain, is_auto_created) VALUES (?, ?, ?, 0)')
          .bind(fromAddr.toLowerCase(), parts[0], parts[1]).run();
      }
    }
  } catch (e) { /* ignore */ }

  let resultId = '';

  if (sendMethod === 'resend') {
    const payload = {
      from: fromAddr,
      to: toAddrs,
      subject: subject,
    };
    if (htmlContent) payload.html = htmlContent;
    if (textContent) payload.text = textContent;
    if (ccAddrs.length) payload.cc = ccAddrs;
    if (bccAddrs.length) payload.bcc = bccAddrs;
    if (body.reply_to) payload.reply_to = body.reply_to;

    // Add attachments for Resend API (separate inline CID images from regular attachments)
    if (attachments.length) {
      payload.attachments = attachments.filter(att => !att.cid).map(att => ({
        filename: att.filename || 'attachment',
        content: att.content, // base64
        content_type: att.content_type || 'application/octet-stream'
      }));
      // Inline CID images go into headers with Content-ID
      const inlineAtts = attachments.filter(att => att.cid);
      if (inlineAtts.length) {
        // Resend doesn't have a separate inline attachment field,
        // but supports Content-Disposition: inline with Content-ID via attachments
        for (const att of inlineAtts) {
          payload.attachments.push({
            filename: att.filename || 'image.png',
            content: att.content,
            content_type: att.content_type || 'image/png',
            headers: {
              'Content-ID': '<' + att.cid + '>',
              'Content-Disposition': 'inline; filename="' + (att.filename || 'image.png') + '"'
            }
          });
        }
      }
      if (!payload.attachments.length) delete payload.attachments;
    }

    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await resp.json();
    if (!resp.ok) {
      return json({ error: result.message || result.error?.message || 'Resend failed' }, resp.status);
    }
    resultId = result.id || '';
  } else if (sendMethod === 'cf_native') {
    // CF native send using send_email binding
    try {
      const msg = createMimeMessage();
      msg.setSender({ addr: fromAddr });
      msg.setRecipient(toAddrs.map(a => ({ addr: a })));
      if (ccAddrs.length) msg.setCc(ccAddrs.map(a => ({ addr: a })));
      msg.setSubject(subject);

      if (htmlContent) {
        msg.addMessage({ contentType: 'text/html', data: htmlContent });
      }
      if (textContent) {
        msg.addMessage({ contentType: 'text/plain', data: textContent });
      }

      // Add attachments
      for (const att of attachments) {
        msg.addAttachment({
          filename: att.filename || 'attachment',
          contentType: att.content_type || 'application/octet-stream',
          data: att.content // base64
        });
      }

      // Send to each recipient
      for (const to of toAddrs) {
        const emailMsg = new EmailMessage(fromAddr, to, msg.asRaw());
        await env.SEND_EMAIL.send(emailMsg);
      }
      resultId = 'cf_' + Date.now();
    } catch (e) {
      return json({ error: 'CF Send failed: ' + e.message }, 500);
    }
  } else if (sendMethod === 'cf_email_service') {
    // CF Email Service — tries Workers Send Email binding first, then CF REST API.
    // Build payload once; both paths share the same shape.
    const cfEsToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;

    const esPayload = {
      to: toAddrs.length === 1 ? toAddrs[0] : toAddrs,
      from: body.from_name ? { email: fromAddr, name: body.from_name } : fromAddr,
      subject: subject,
    };
    if (htmlContent) esPayload.html = htmlContent;
    if (textContent) esPayload.text = textContent;
    if (ccAddrs.length) esPayload.cc = ccAddrs;
    if (bccAddrs.length) esPayload.bcc = bccAddrs;
    if (body.reply_to) esPayload.replyTo = body.reply_to;
    if (attachments.length) {
      esPayload.attachments = attachments.map(att => ({
        content: att.content,
        filename: att.filename || 'attachment',
        type: att.content_type || 'application/octet-stream',
        disposition: att.cid ? 'inline' : 'attachment',
        ...(att.cid ? { contentId: att.cid } : {})
      }));
    }

    // Path A: Workers Send Email binding
    if (env.SEND_EMAIL) {
      try {
        const result = await env.SEND_EMAIL.send(esPayload);
        resultId = result?.messageId || ('cf_es_' + Date.now());
      } catch (bindErr) {
        // Binding failed — fall through to REST API below
        if (!cfEsToken) {
          return json({ error: 'CF Email Service (binding) failed: ' + bindErr.message + '. No CF API token configured for REST fallback — add one in Settings.' }, 500);
        }
        // cfEsToken is available; proceed to Path B
      }
    }

    // Path B: CF Email Service REST API (used when binding absent or binding failed)
    if (!resultId && cfEsToken) {
      const cfAccountId = await getCfAccountId(db, cfEsToken);
      if (!cfAccountId) {
        return json({ error: 'CF Email Service REST: could not determine Cloudflare Account ID. Check that the CF API token in Settings has Account:Read permission.' }, 500);
      }
      try {
        const restPayload = {
          to: toAddrs.length === 1 ? toAddrs[0] : toAddrs,
          from: body.from_name ? { address: fromAddr, name: body.from_name } : fromAddr,
          subject: subject,
        };
        if (htmlContent) restPayload.html = htmlContent;
        if (textContent) restPayload.text = textContent;
        if (ccAddrs.length) restPayload.cc = ccAddrs;
        if (bccAddrs.length) restPayload.bcc = bccAddrs;
        if (body.reply_to) restPayload.reply_to = body.reply_to;
        if (attachments.length) {
          restPayload.attachments = attachments.map(att => ({
            content: att.content,
            filename: att.filename || 'attachment',
            type: att.content_type || 'application/octet-stream',
            disposition: att.cid ? 'inline' : 'attachment',
            ...(att.cid ? { contentId: att.cid } : {})
          }));
        }
        const resp = await fetchWithTimeout(`https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/email/sending/send`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${cfEsToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(restPayload)
        });
        const result = await resp.json();
        if (!resp.ok) {
          const cfErrCode = result.errors?.[0]?.code || '';
          const cfErrMsg  = result.errors?.[0]?.message || '';
          // email.sending_disabled means the CF account has not enabled Email Sending.
          // Auto-fallback to Resend if configured; otherwise surface clear instructions.
          if (cfErrCode === 'email.sending_disabled' || cfErrMsg.includes('sending_disabled') || cfErrMsg.includes('email.sending')) {
            const fbResendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
            if (fbResendKey) {
              // silently promote to Resend for this request
              sendMethod = 'resend';
              // fall through — resultId still empty, Resend block runs below
            } else {
              return json({ error: 'CF Email Sending is disabled for your Cloudflare account. To enable it: Cloudflare Dashboard → Email → Email Routing → enable a domain, which activates Email Sending. Alternatively, add a Resend API key in Settings as a fallback.' }, 503);
            }
          } else {
            return json({ error: 'CF Email Service send failed: ' + (cfErrMsg || JSON.stringify(result.errors)) }, resp.status);
          }
        } else {
          resultId = 'cf_es_rest_' + Date.now();
        }
      } catch (restErr) {
        return json({ error: 'CF Email Service REST send failed: ' + restErr.message }, 500);
      }
    }

    if (!resultId) {
      return json({ error: 'CF Email Service not available: SEND_EMAIL binding is missing and no CF API token is configured in Settings.' }, 400);
    }

    // If CF failed with sending_disabled and we promoted to Resend, run the Resend path now
    if (sendMethod === 'resend' && !resultId) {
      const fbResendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
      const fbPayload = {
        from: fromAddr, to: toAddrs, subject: subject,
        ...(htmlContent ? { html: htmlContent } : {}),
        ...(textContent ? { text: textContent } : {}),
        ...(ccAddrs.length ? { cc: ccAddrs } : {}),
        ...(bccAddrs.length ? { bcc: bccAddrs } : {}),
        ...(body.reply_to ? { reply_to: body.reply_to } : {}),
      };
      if (attachments.length) {
        fbPayload.attachments = attachments.filter(a => !a.cid).map(a => ({
          filename: a.filename || 'attachment', content: a.content,
          content_type: a.content_type || 'application/octet-stream'
        }));
      }
      const fbResp = await fetchWithTimeout('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${fbResendKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(fbPayload)
      });
      const fbResult = await fbResp.json();
      if (!fbResp.ok) return json({ error: 'CF email sending disabled; Resend fallback also failed: ' + (fbResult.message || fbResult.name || JSON.stringify(fbResult)) }, fbResp.status);
      resultId = fbResult.id || ('resend_fb_' + Date.now());
    }
  }

  // Store sent email record (send_provider tracks which backend was used)
  await db.prepare(`INSERT INTO sent_emails (from_addr, from_name, to_addrs, cc_addrs, bcc_addrs, subject, html_content, text_content, resend_id, send_provider)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    fromAddr, body.from_name || '', JSON.stringify(toAddrs),
    JSON.stringify(ccAddrs), JSON.stringify(bccAddrs),
    subject, htmlContent, textContent, resultId, sendMethod
  ).run();

  // Get the sent email ID
  const sentIdResult = await db.prepare('SELECT last_insert_rowid() as id').first();
  const sentId = sentIdResult.id;

  // Store sent attachments in R2 and record metadata in DB
  if (attachments.length) {
    for (const att of attachments) {
      let r2Key = '';
      if (env.R2 && att.content) {
        try {
          r2Key = `sent-attachments/${sentId}/${att.filename || 'attachment'}`;
          const fileData = Uint8Array.from(atob(att.content), c => c.charCodeAt(0));
          await env.R2.put(r2Key, fileData, {
            httpMetadata: { contentType: att.content_type || 'application/octet-stream' }
          });
        } catch (e) { console.error('R2 sent attachment error:', e); r2Key = ''; }
      }
      const size = att.content ? Math.round(att.content.length * 3 / 4) : 0;
      await db.prepare('INSERT INTO sent_attachments (sent_email_id, filename, content_type, size, r2_key, cid) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(sentId, att.filename || 'attachment', att.content_type || 'application/octet-stream', size, r2Key, att.cid || '').run();
    }
  }

  return json({ success: true, id: resultId, sent_id: sentId, method: sendMethod, can_poll: sendMethod === 'resend' });
}

// ---- Shared Inbound Email Processing ----
async function processInboundEmail(db, env, { sender, to, subject, html, text, attachments, rawBytes }) {
  // Extract pure email address from "to" (handle formats like "Name <email@domain>" or multiple addresses)
  let toAddr = to || '';
  const angleMatch = toAddr.match(/<([^>]+)>/);
  if (angleMatch) toAddr = angleMatch[1];
  toAddr = toAddr.split(',')[0].trim().toLowerCase();

  // Find or auto-create mailbox
  let mbx = await db.prepare('SELECT * FROM mailboxes WHERE address = ?').bind(toAddr).first();
  if (!mbx) {
    const autoCreate = await getSetting(db, 'auto_create_enabled');
    // Default to auto-create enabled if setting is not explicitly disabled
    const shouldAutoCreate = autoCreate === 'true' || autoCreate === '1' || autoCreate === null || autoCreate === undefined;
    if (shouldAutoCreate) {
      const parts = toAddr.split('@');
      if (parts.length === 2) {
        const minLen = parseInt(await getSetting(db, 'auto_create_min_length') || '3');
        const maxLen = parseInt(await getSetting(db, 'auto_create_max_length') || '30');
        if (parts[0].length >= minLen && parts[0].length <= maxLen) {
          await db.prepare('INSERT OR IGNORE INTO mailboxes (address, local_part, domain, is_auto_created) VALUES (?, ?, ?, 1)')
            .bind(toAddr, parts[0], parts[1]).run();
          mbx = await db.prepare('SELECT * FROM mailboxes WHERE address = ?').bind(toAddr).first();
        }
      }
    }
    if (!mbx) return;
  }

  // Extract verification code — try text first, fall back to stripped html
  // Also handle the case where text/plain part is actually HTML (some senders do this)
  const stripForExtraction = (s) => (s || '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ').trim();
  const textIsHtml = /^<!doctype\s+html|^<html[\s>]/i.test((text || '').trimStart());
  const cleanText = textIsHtml ? stripForExtraction(text) : (text || '');
  let verificationCode = extractVerificationCode(subject, cleanText);
  if (!verificationCode && html) verificationCode = extractVerificationCode(subject, stripForExtraction(html));

  // Generate preview
  const preview = generatePreview(html, text);

  // Store message
  const result = await db.prepare(`INSERT INTO messages (mailbox_id, sender, to_addr, subject, preview, html_content, text_content, verification_code, eml_r2_key)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    mbx.id, sender, toAddr, subject, preview, html, text, verificationCode, ''
  ).run();

  const messageId = result.meta.last_row_id;

  // Store raw EML in R2
  if (env.R2) {
    try {
      const emlKey = `eml/${mbx.id}/${messageId}.eml`;
      const emlContent = rawBytes || buildSimpleEml(sender, to, subject, html, text);
      await env.R2.put(emlKey, emlContent);
      await db.prepare('UPDATE messages SET eml_r2_key = ? WHERE id = ?').bind(emlKey, messageId).run();
    } catch (e) { console.error('R2 EML store error:', e); }
  }

  // Store attachments in R2 (fallback to D1 if R2 unavailable)
  if (attachments && Array.isArray(attachments) && attachments.length) {
    for (const att of attachments) {
      let r2Key = '';
      const hasContent = att.content && ((att.content instanceof Uint8Array && att.content.length > 0) || (typeof att.content === 'string' && att.content.length > 0));
      if (env.R2 && hasContent) {
        try {
          r2Key = `attachments/${mbx.id}/${messageId}/${att.filename || 'attachment'}`;
          let fileData;
          if (att.content instanceof Uint8Array) {
            fileData = att.content;
          } else if (typeof att.content === 'string') {
            try {
              fileData = Uint8Array.from(atob(att.content), c => c.charCodeAt(0));
            } catch {
              fileData = new TextEncoder().encode(att.content);
            }
          } else {
            fileData = new TextEncoder().encode(String(att.content));
          }
          await env.R2.put(r2Key, fileData, {
            httpMetadata: { contentType: att.content_type || 'application/octet-stream' }
          });
        } catch (e) {
          console.error('R2 attachment store error:', e);
          r2Key = '';
        }
      }
      const d1Content = r2Key ? '' : (typeof att.content === 'string' ? att.content : '');
      await db.prepare('INSERT INTO attachments (message_id, filename, content_type, size, r2_key, content) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(messageId, att.filename || 'attachment', att.content_type || '', att.size || 0, r2Key, d1Content).run();
    }
  }

  // Telegram notification
  await sendTelegramNotification(db, { sender, to: toAddr, subject }, verificationCode);

  // Email forwarding
  await forwardEmail(db, env, { sender, to: toAddr, subject, html, text });
}

// ---- Inbound Webhook (Resend/external webhook fallback) ----
async function handleInboundWebhook(request, env, db, json) {
  const body = await request.json();
  const sender = body.from || '';
  const to = body.to || '';
  const subject = body.subject || '(no subject)';
  const html = body.html || '';
  const text = body.text || body.plain || '';

  const attachments = (body.attachments || []).map(att => ({
    filename: att.filename || 'attachment',
    content_type: att.content_type || '',
    size: att.size || 0,
    content: att.content || ''
  }));

  const rawBytes = body.raw ? new TextEncoder().encode(body.raw) : null;

  await processInboundEmail(db, env, {
    sender, to, subject, html, text, attachments, rawBytes
  });

  return json({ success: true });
}

// ---- Sent Emails ----
async function handleListSent(db, url, json) {
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = parseInt(url.searchParams.get('limit') || '20');
  const offset = (page - 1) * limit;
  const from = url.searchParams.get('from');
  let query = 'SELECT id, from_addr, from_name, to_addrs, subject, status, send_provider, status_updated_at, created_at, is_favorite, substr(text_content, 1, 120) as preview, substr(html_content, 1, 600) as html_snippet FROM sent_emails WHERE (is_deleted = 0 OR is_deleted IS NULL)';
  let countQuery = 'SELECT COUNT(*) as total FROM sent_emails WHERE (is_deleted = 0 OR is_deleted IS NULL)';
  const params = [];
  const countParams = [];
  if (from) {
    query += ' AND from_addr = ?';
    countQuery += ' AND from_addr = ?';
    params.push(from);
    countParams.push(from);
  }
  const isFavorite = url.searchParams.get('is_favorite');
  if (isFavorite === '1') {
    query += ' AND (is_favorite = 1)';
    countQuery += ' AND (is_favorite = 1)';
  }
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const [emails, countResult] = await Promise.all([
    db.prepare(query).bind(...params).all(),
    countParams.length ? db.prepare(countQuery).bind(...countParams).first() : db.prepare(countQuery).first()
  ]);
  // Enrich preview: strip HTML from text_content preview, fall back to html_content if empty
  const stripHtmlPreview = (s) => (s || '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-zA-Z#0-9]+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .substring(0, 120);
  const processed = (emails.results || []).map(e => {
    let preview = stripHtmlPreview(e.preview);
    if (!preview && e.html_snippet) {
      preview = stripHtmlPreview(e.html_snippet);
    }
    const { html_snippet, ...rest } = e;
    return { ...rest, preview };
  });
  return json({ emails: processed, total: countResult.total, page, limit, pages: Math.ceil(countResult.total / limit) });
}

async function handleToggleSentFavorite(path, db, json) {
  const id = parseInt(path.split('/')[3]);
  const email = await db.prepare('SELECT is_favorite FROM sent_emails WHERE id = ?').bind(id).first();
  if (!email) return json({ error: 'Not found' }, 404);
  const newVal = email.is_favorite ? 0 : 1;
  await db.prepare('UPDATE sent_emails SET is_favorite = ? WHERE id = ?').bind(newVal, id).run();
  return json({ success: true, is_favorite: newVal });
}

async function handleGetSentEmail(path, db, json) {
  const id = parseInt(path.split('/').pop());
  const email = await db.prepare('SELECT * FROM sent_emails WHERE id = ?').bind(id).first();
  if (!email) return json({ error: 'Not found' }, 404);
  // Get attachments for this sent email
  let attachments = [];
  try {
    const atts = await db.prepare('SELECT id, filename, content_type, size, r2_key, cid FROM sent_attachments WHERE sent_email_id = ?').bind(id).all();
    attachments = atts.results || [];
  } catch (e) { /* table may not exist yet */ }
  return json({ email, attachments });
}

async function handleDeleteSentEmail(path, db, json) {
  const id = parseInt(path.split('/').pop());
  // Soft delete: move to trash
  await db.prepare('UPDATE sent_emails SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id = ?').bind(id).run();
  return json({ success: true });
}

// ---- Resend Delivery Webhook (public, Svix-signed) ----
// Receives events: email.delivered / email.bounced / email.delivery_delayed / email.complained / email.clicked / email.opened
async function handleResendDeliveryWebhook(request, db, json) {
  const rawBody = await request.text();

  // Verify Svix signature when webhook secret is configured
  const webhookSecret = await getSetting(db, 'resend_webhook_secret');
  if (webhookSecret) {
    const svixId        = request.headers.get('svix-id');
    const svixTimestamp = request.headers.get('svix-timestamp');
    const svixSig       = request.headers.get('svix-signature');

    if (!svixId || !svixTimestamp || !svixSig) {
      return json({ error: 'Missing Svix headers' }, 400);
    }

    // Replay-attack guard: reject if timestamp is more than 5 minutes old
    const ts = parseInt(svixTimestamp, 10);
    if (Math.abs(Math.floor(Date.now() / 1000) - ts) > 300) {
      return json({ error: 'Webhook timestamp too old' }, 400);
    }

    // HMAC-SHA256 of "{svix-id}.{svix-timestamp}.{rawBody}"
    // Resend webhook secrets are prefixed with "whsec_" followed by base64-encoded key
    const toSign = `${svixId}.${svixTimestamp}.${rawBody}`;
    const rawSecret = webhookSecret.startsWith('whsec_') ? webhookSecret.slice(6) : webhookSecret;
    const keyBytes = Uint8Array.from(atob(rawSecret), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(toSign));
    const computed = 'v1,' + btoa(String.fromCharCode(...new Uint8Array(sigBuf)));

    // svix-signature may contain multiple space-separated "v1,<base64>" values
    const valid = svixSig.split(' ').some(s => s === computed);
    if (!valid) return json({ error: 'Invalid webhook signature' }, 403);
  }

  let body;
  try { body = JSON.parse(rawBody); } catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const eventType = body.type || '';
  const data = body.data || {};
  const emailId = data.email_id || data.id || '';

  if (!emailId) return json({ success: true });

  const statusMap = {
    'email.sent':             'sent',
    'email.delivered':        'delivered',
    'email.delivery_delayed': 'delayed',
    'email.complained':       'complained',
    'email.bounced':          'bounced',
    'email.clicked':          'clicked',
    'email.opened':           'opened',
    'email.failed':           'bounced',
    'email.suppressed':       'bounced',
  };

  const newStatus = statusMap[eventType];
  if (!newStatus) return json({ success: true });

  const deliveryError = (data.bounce && (data.bounce.message || data.bounce.type)) || null;

  try {
    if (deliveryError) {
      await db.prepare(
        'UPDATE sent_emails SET status = ?, status_updated_at = CURRENT_TIMESTAMP, delivery_error = ? WHERE resend_id = ? AND (is_deleted = 0 OR is_deleted IS NULL)'
      ).bind(newStatus, deliveryError, emailId).run();
    } else {
      await db.prepare(
        'UPDATE sent_emails SET status = ?, status_updated_at = CURRENT_TIMESTAMP WHERE resend_id = ? AND (is_deleted = 0 OR is_deleted IS NULL)'
      ).bind(newStatus, emailId).run();
    }
  } catch (e) { /* ignore */ }

  return json({ success: true });
}

// ---- Manual status refresh by polling Resend API ----
// First checks DB (webhook may have already updated), only calls Resend API if still non-terminal
async function handleCheckSentStatus(path, db, env, json) {
  const match = path.match(/\/api\/sent\/(\d+)\/status/);
  if (!match) return json({ error: 'Invalid path' }, 400);
  const id = parseInt(match[1]);

  const email = await db.prepare(
    'SELECT id, resend_id, status, delivery_error, send_provider FROM sent_emails WHERE id = ? AND (is_deleted = 0 OR is_deleted IS NULL)'
  ).bind(id).first();
  if (!email) return json({ error: 'Not found' }, 404);

  // Only Resend-sent emails have a queryable status
  if (!email.resend_id || !String(email.resend_id).startsWith('re_')) {
    return json({ status: email.status || 'sent', can_check: false });
  }

  // If webhook already updated to a terminal status, return immediately without calling Resend API
  const terminalStatuses = { delivered: 1, bounced: 1, complained: 1 };
  if (terminalStatuses[email.status]) {
    return json({ status: email.status, can_check: true, error: email.delivery_error || null });
  }

  // Non-terminal — fall back to polling Resend API
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  if (!resendKey) return json({ error: 'Resend API key not configured' }, 400);

  let resendData;
  try {
    const resp = await fetchWithTimeout(
      `https://api.resend.com/emails/${email.resend_id}`,
      { headers: { 'Authorization': `Bearer ${resendKey}` } },
      8000
    );
    if (!resp.ok) return json({ status: email.status || 'sent', can_check: true, error: `Resend API error: ${resp.status}` });
    resendData = await resp.json();
  } catch (e) {
    return json({ status: email.status || 'sent', can_check: true, error: e.message });
  }

  const rawStatus = resendData.last_event || 'sent';
  const normalMap = {
    'queued': 'sent', 'scheduled': 'sent', 'canceled': 'sent',
    'sent': 'sent', 'delivered': 'delivered',
    'delivery_delayed': 'delayed', 'complained': 'complained', 'bounced': 'bounced',
    'clicked': 'clicked', 'opened': 'opened',
    'failed': 'bounced', 'suppressed': 'bounced',
  };
  const mappedStatus = normalMap[rawStatus] || rawStatus;

  await db.prepare(
    'UPDATE sent_emails SET status = ?, status_updated_at = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(mappedStatus, id).run();

  return json({ status: mappedStatus, can_check: true, last_event: rawStatus });
}

// ---- Trash (Deleted Items) ----
async function handleListTrash(db, url, json) {
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = parseInt(url.searchParams.get('limit') || '20');
  const offset = (page - 1) * limit;
  const mailboxId = url.searchParams.get('mailbox_id');

  // Fetch all deleted items without per-query pagination, then merge+sort+paginate in memory
  let msgQuery = `SELECT id, 'inbox' as type, mailbox_id, sender, to_addr, subject, preview, received_at as date, deleted_at FROM messages WHERE is_deleted = 1`;
  let sentQuery = `SELECT id, 'sent' as type, from_addr as sender, to_addrs as to_addr, subject, '' as preview, created_at as date, deleted_at FROM sent_emails WHERE is_deleted = 1`;
  let countMsgQuery = 'SELECT COUNT(*) as c FROM messages WHERE is_deleted = 1';
  let countSentQuery = 'SELECT COUNT(*) as c FROM sent_emails WHERE is_deleted = 1';
  const msgParams = [];
  const sentParams = [];
  const countMsgParams = [];
  const countSentParams = [];

  if (mailboxId) {
    msgQuery += ' AND mailbox_id = ?';
    countMsgQuery += ' AND mailbox_id = ?';
    msgParams.push(parseInt(mailboxId));
    countMsgParams.push(parseInt(mailboxId));
    // For sent emails, filter by the mailbox address
    const mbx = await db.prepare('SELECT address FROM mailboxes WHERE id = ?').bind(parseInt(mailboxId)).first();
    if (mbx) {
      sentQuery += ' AND from_addr = ?';
      countSentQuery += ' AND from_addr = ?';
      sentParams.push(mbx.address);
      countSentParams.push(mbx.address);
    }
  }

  msgQuery += ' ORDER BY deleted_at DESC';
  sentQuery += ' ORDER BY deleted_at DESC';

  const [deletedMessages, deletedSent, countMsg, countSent] = await Promise.all([
    msgParams.length ? db.prepare(msgQuery).bind(...msgParams).all() : db.prepare(msgQuery).all(),
    sentParams.length ? db.prepare(sentQuery).bind(...sentParams).all() : db.prepare(sentQuery).all(),
    countMsgParams.length ? db.prepare(countMsgQuery).bind(...countMsgParams).first() : db.prepare(countMsgQuery).first(),
    countSentParams.length ? db.prepare(countSentQuery).bind(...countSentParams).first() : db.prepare(countSentQuery).first(),
  ]);

  // Merge all results, sort by deleted_at desc, then paginate
  const allItems = [
    ...(deletedMessages.results || []),
    ...(deletedSent.results || [])
  ].sort((a, b) => new Date(b.deleted_at || 0) - new Date(a.deleted_at || 0));

  const total = (countMsg.c || 0) + (countSent.c || 0);
  return json({
    items: allItems.slice(offset, offset + limit),
    total,
    page, limit,
    pages: Math.ceil(total / limit)
  });
}

async function handleRestoreFromTrash(request, db, json) {
  const { items } = await request.json();
  if (!items || !items.length) return json({ error: 'No items provided' }, 400);
  let restored = 0;
  for (const item of items) {
    if (item.type === 'inbox') {
      await db.prepare('UPDATE messages SET is_deleted = 0, deleted_at = NULL WHERE id = ?').bind(item.id).run();
      restored++;
    } else if (item.type === 'sent') {
      await db.prepare('UPDATE sent_emails SET is_deleted = 0, deleted_at = NULL WHERE id = ?').bind(item.id).run();
      restored++;
    }
  }
  return json({ success: true, restored });
}

async function handlePermanentDelete(request, db, env, json) {
  const { items } = await request.json();
  if (!items || !items.length) return json({ error: 'No items provided' }, 400);
  let deleted = 0;
  for (const item of items) {
    if (item.type === 'inbox') {
      await cleanupMessageR2(db, env, item.id);
      await db.prepare('DELETE FROM messages WHERE id = ? AND is_deleted = 1').bind(item.id).run();
      deleted++;
    } else if (item.type === 'sent') {
      // Clean up R2 attachments for sent emails
      if (env.R2) {
        try {
          const sentAtts = await db.prepare('SELECT r2_key FROM sent_attachments WHERE sent_email_id = ?').bind(item.id).all();
          for (const att of (sentAtts.results || [])) {
            if (att.r2_key) await env.R2.delete(att.r2_key);
          }
        } catch (e) { /* best-effort cleanup */ }
      }
      await db.prepare('DELETE FROM sent_emails WHERE id = ? AND is_deleted = 1').bind(item.id).run();
      deleted++;
    }
  }
  return json({ success: true, deleted });
}

async function handleClearTrash(db, env, json) {
  // Permanently delete all trashed messages
  const trashedMsgs = await db.prepare('SELECT id FROM messages WHERE is_deleted = 1').all();
  for (const msg of trashedMsgs.results) {
    await cleanupMessageR2(db, env, msg.id);
  }
  await db.prepare('DELETE FROM messages WHERE is_deleted = 1').run();
  await db.prepare('DELETE FROM sent_emails WHERE is_deleted = 1').run();
  return json({ success: true });
}

// ---- Domains ----
async function handleListDomains(env, db, json) {
  const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  const domainProvider = await getSetting(db, 'domain_provider') || 'resend';

  let resendDomains = [];
  if (resendKey && domainProvider === 'resend') {
    try {
      const resp = await fetch('https://api.resend.com/domains', {
        headers: { 'Authorization': `Bearer ${resendKey}` }
      });
      const data = await resp.json();
      resendDomains = data.data || [];
    } catch (e) { /* ignore */ }
  }

  let cfEmailServiceDomains = [];
  if (cfToken && domainProvider === 'cf') {
    // List CF Email Service subdomains for each zone
    try {
      const zoneResp = await fetch('https://api.cloudflare.com/client/v4/zones?per_page=50&status=active', {
        headers: { 'Authorization': `Bearer ${cfToken}` }
      });
      const zoneData = await zoneResp.json();
      const zones = zoneData.result || [];
      for (const zone of zones) {
        try {
          const subResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones/${zone.id}/email/sending/subdomains`,
            { headers: { 'Authorization': `Bearer ${cfToken}` } }
          );
          const subData = await subResp.json();
          const subs = subData.result || [];
          for (const sub of subs) {
            cfEmailServiceDomains.push({
              id: sub.tag,
              name: sub.name,
              status: sub.enabled ? 'verified' : 'pending',
              zone_id: zone.id,
              zone_name: zone.name,
              provider: 'cf'
            });
          }
        } catch (e) { /* ignore per-zone errors */ }
      }
    } catch (e) { /* ignore */ }
  }

  let cfZones = [];
  if (cfToken) {
    try {
      const resp = await fetch('https://api.cloudflare.com/client/v4/zones?per_page=50&status=active', {
        headers: { 'Authorization': `Bearer ${cfToken}` }
      });
      const data = await resp.json();
      cfZones = (data.result || []).map(z => ({ id: z.id, name: z.name }));
    } catch (e) { /* ignore */ }
  }

  // "configured" is used by the frontend to show domains in the "Create Mailbox" dropdown
  const configured = domainProvider === 'resend' 
    ? resendDomains.filter(d => d.status === 'verified').map(d => d.name)
    : cfEmailServiceDomains.filter(d => d.status === 'verified').map(d => d.name);

  return json({
    configured: configured,
    resend: domainProvider === 'resend' ? resendDomains : [],
    cf_email_service: cfEmailServiceDomains,
    cloudflare: cfZones,
    domain_provider: domainProvider
  });
}

async function handleEnableDomain(request, env, db, json) {
  const { domain, zone_id } = await request.json();
  const domainProvider = await getSetting(db, 'domain_provider') || 'resend';

  if (domainProvider === 'cf') {
    // CF Email Service: create sending subdomain
    const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
    if (!cfToken) return json({ error: 'Cloudflare API token not configured' }, 400);
    if (!zone_id) return json({ error: 'zone_id required for CF Email Service' }, 400);

    const resp = await fetchWithTimeout(
      `https://api.cloudflare.com/client/v4/zones/${zone_id}/email/sending/subdomains`,
      {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: domain })
      }
    );
    const result = await resp.json();
    if (!resp.ok) return json({ error: result.errors?.[0]?.message || 'Failed to add domain to CF Email Service' }, resp.status);
    return json({ success: true, domain: { id: result.result?.tag, name: domain, status: result.result?.enabled ? 'verified' : 'pending', provider: 'cf', zone_id } });
  } else {
    // Resend: original logic
    const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
    if (!resendKey) return json({ error: 'Resend API key not configured' }, 400);

    const resp = await fetch('https://api.resend.com/domains', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: domain })
    });
    const result = await resp.json();
    if (!resp.ok) return json({ error: result.message || 'Failed to add domain' }, resp.status);
    return json({ success: true, domain: result });
  }
}

// Auto-create DNS records in Cloudflare for a Resend domain
async function autoCreateDnsRecords(cfToken, resendKey, domainId, domainName, zoneIdParam) {
  const results = [];
  try {
    // Get required DNS records from Resend (with retry for race condition)
    let records = [];
    for (let attempt = 0; attempt < 3; attempt++) {
      const domResp = await fetchWithTimeout(`https://api.resend.com/domains/${domainId}`, {
        headers: { 'Authorization': `Bearer ${resendKey}` }
      });
      const domData = await domResp.json();
      records = domData.records || [];
      if (records.length > 0) break;
      // Resend hasn't populated DNS records yet, wait and retry
      await new Promise(r => setTimeout(r, 2000));
    }
    if (!records.length) {
      results.push({ status: 'error', message: 'Resend returned no DNS records after retries (domain may still be initializing)' });
      return results;
    }

    // Use zone_id directly if provided, otherwise fallback to lookup
    let zoneId = zoneIdParam;
    if (!zoneId) {
      const zoneResp = await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones?name=${domainName}&status=active`, {
        headers: { 'Authorization': `Bearer ${cfToken}` }
      });
      const zoneData = await zoneResp.json();
      const zones = zoneData.result || [];
      if (!zones.length) {
        results.push({ status: 'error', message: `Zone not found for ${domainName}` });
        return results;
      }
      zoneId = zones[0].id;
    }

    // Create each DNS record
    for (const record of records) {
      const type = record.record_type || record.type;
      const rawName = record.name || '';
      const value = record.value || record.expected_value || '';
      if (!type || !value) continue;

      // Resend returns names that may include domain parts (e.g. "resend._domainkey.niuma" for domain "niuma.qzz.io")
      // CF zone is the domain itself, so we need to strip overlapping domain parts
      // to avoid duplication like "resend._domainkey.niuma.niuma.qzz.io"
      let cfName = rawName;
      if (domainName) {
        const domainParts = domainName.split('.');
        for (let i = domainParts.length; i >= 1; i--) {
          const suffix = '.' + domainParts.slice(0, i).join('.');
          if (cfName.endsWith(suffix)) {
            cfName = cfName.slice(0, -suffix.length) || domainName;
            break;
          }
        }
      }
      // Build FQDN for CF queries
      let queryName = cfName;
      if (domainName && !cfName.endsWith('.' + domainName) && cfName !== domainName) {
        queryName = cfName + '.' + domainName;
      }

      const cfRecord = { type, name: cfName, content: value, ttl: 1 };
      if (type === 'MX') cfRecord.priority = record.priority || 10;

      try {
        // Check if record already exists (use FQDN for query)
        const existResp = await fetchWithTimeout(
          `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(queryName)}`,
          { headers: { 'Authorization': `Bearer ${cfToken}` } }
        );
        const existData = await existResp.json();
        const exactMatch = (existData.result || []).find(r => r.content === value);

        if (exactMatch) {
          results.push({ type, name: cfName, status: 'exists' });
          continue;
        }

        // Check if same type+name exists with different content (e.g. rotated DKIM key)
        const sameTypeNameRecords = (existData.result || []).filter(r => r.type === type);
        // For CNAME/TXT DKIM records: update the existing one instead of creating duplicate
        if (sameTypeNameRecords.length > 0 && (type === 'CNAME' || (type === 'TXT' && cfName.includes('_domainkey')))) {
          const old = sameTypeNameRecords[0];
          const updateResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${old.id}`,
            {
              method: 'PUT',
              headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify(cfRecord)
            }
          );
          const updateData = await updateResp.json();
          if (updateData.success) {
            const verifyResp = await fetchWithTimeout(
              `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(queryName)}`,
              { headers: { 'Authorization': `Bearer ${cfToken}` } }
            );
            const verifyData = await verifyResp.json();
            const verified = (verifyData.result || []).find(r => r.content === value);
            results.push({
              type, name: cfName,
              status: verified ? 'updated' : 'updated_unverified',
              cf_name: verified ? verified.name : null
            });
          } else {
            results.push({
              type, name: cfName,
              status: 'failed',
              error: JSON.stringify(updateData.errors || updateData)
            });
          }
          continue;
        }

        // Create the record
        const createResp = await fetchWithTimeout(
          `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
          {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(cfRecord)
          }
        );
        const createData = await createResp.json();
        if (createData.success) {
          // Read back from CF to confirm record was created with correct name
          const verifyResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(queryName)}`,
            { headers: { 'Authorization': `Bearer ${cfToken}` } }
          );
          const verifyData = await verifyResp.json();
          const verified = (verifyData.result || []).find(r => r.content === value);
          results.push({
            type, name: cfName,
            status: verified ? 'created' : 'created_unverified',
            cf_name: verified ? verified.name : null,
            error: verified ? null : 'Record created but not found when reading back from CF'
          });
        } else {
          results.push({
            type, name: cfName,
            status: 'failed',
            error: JSON.stringify(createData.errors || createData),
            sent: cfRecord
          });
        }
      } catch (e) {
        results.push({ type, name: cfName, status: 'error', error: e.message });
      }
    }
  } catch (e) {
    results.push({ status: 'error', message: e.message });
  }
  return results;
}

async function handleDisableDomain(request, env, db, json) {
  const { domain_id, zone_id, domain_name } = await request.json();
  const domainProvider = await getSetting(db, 'domain_provider') || 'resend';
  const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;

  if (domainProvider === 'cf') {
    // CF Email Service: delete sending subdomain
    if (!cfToken) return json({ error: 'Cloudflare API token not configured' }, 400);
    const zoneId = zone_id;
    if (!zoneId || !domain_id) return json({ error: 'zone_id and domain_id required' }, 400);

    const resp = await fetchWithTimeout(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/email/sending/subdomains/${domain_id}`,
      {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${cfToken}` }
      },
      10000
    );
    if (!resp.ok) {
      const result = await resp.json();
      return json({ error: result.errors?.[0]?.message || 'Failed to remove domain from CF Email Service' }, resp.status);
    }

    // Also clean up Email Routing if configured
    const cleanup = { dns_deleted: 0, dns_errors: [], email_routing_deleted: false };
    if (zoneId && domain_name) {
      try {
        // Delete CF Email Routing MX records
        try {
          const mxResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=MX&name=${domain_name}`,
            { headers: { 'Authorization': `Bearer ${cfToken}` } },
            10000
          );
          const mxData = await mxResp.json();
          const cfMxRecords = (mxData.result || []).filter(r => r.content && r.content.includes('.mx.cloudflare.net'));
          for (const rec of cfMxRecords) {
            try {
              await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${rec.id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${cfToken}` }
              }, 10000);
              cleanup.dns_deleted++;
            } catch (e) {
              cleanup.dns_errors.push(`Failed to delete MX ${rec.content}: ${e.message}`);
            }
          }
        } catch (e) {
          cleanup.dns_errors.push(`Failed to query MX records: ${e.message}`);
        }

        // Reset catch-all Email Routing rule
        try {
          await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/email/routing/rules/catch_all`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              enabled: false,
              matchers: [{ type: 'all' }],
              actions: [{ type: 'drop' }]
            })
          }, 10000);
          cleanup.email_routing_deleted = true;
        } catch (e) {
          cleanup.dns_errors.push(`Failed to disable catch-all: ${e.message}`);
        }
      } catch (e) {
        cleanup.dns_errors.push('Cleanup error: ' + e.message);
      }
    }

    return json({ success: true, cleanup });
  }

  // Resend: original logic
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  if (!resendKey) return json({ error: 'Resend API key not configured' }, 400);

  // 1. Get domain info from Resend before deleting (need the domain name and DNS records)
  let domainName = '';
  let dnsRecords = [];
  try {
    const infoResp = await fetchWithTimeout(`https://api.resend.com/domains/${domain_id}`, {
      headers: { 'Authorization': `Bearer ${resendKey}` }
    }, 10000);
    const infoData = await infoResp.json();
    domainName = infoData.name || '';
    dnsRecords = infoData.records || [];
  } catch (e) { /* continue anyway */ }

  // 2. Delete domain from Resend
  const resp = await fetchWithTimeout(`https://api.resend.com/domains/${domain_id}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${resendKey}` }
  }, 10000);
  if (!resp.ok) return json({ error: 'Failed to remove domain from Resend' }, resp.status);

  // 3. Clean up DNS records and Email Routing in Cloudflare
  const cleanup = { dns_deleted: 0, dns_errors: [], email_routing_deleted: false };
  if (cfToken && domainName) {
    try {
      // Use zone_id if provided, otherwise look up by domain name
      let zoneId = zone_id || null;
      if (!zoneId) {
        // Try exact match first, then try parent domains for subdomains
        const domainParts = domainName.split('.');
        for (let i = 0; i < domainParts.length - 1 && !zoneId; i++) {
          const tryName = domainParts.slice(i).join('.');
          const zoneResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones?name=${tryName}&status=active`,
            { headers: { 'Authorization': `Bearer ${cfToken}` } },
            10000
          );
          const zoneData = await zoneResp.json();
          const zones = zoneData.result || [];
          if (zones.length) zoneId = zones[0].id;
        }
      }

      if (zoneId) {
        // Delete Resend DNS records (DKIM, SPF, MX etc.)
        for (const record of dnsRecords) {
          const type = record.record_type || record.type;
          const rawName = record.name || '';
          if (!type || !rawName) continue;
          // Strip overlapping domain parts from Resend name (same logic as creation)
          let cfName = rawName;
          const domainParts = domainName.split('.');
          for (let i = domainParts.length; i >= 1; i--) {
            const suffix = '.' + domainParts.slice(0, i).join('.');
            if (cfName.endsWith(suffix)) {
              cfName = cfName.slice(0, -suffix.length) || domainName;
              break;
            }
          }
          // Build FQDN for query
          let queryName = cfName;
          if (!cfName.endsWith('.' + domainName) && cfName !== domainName) {
            queryName = cfName + '.' + domainName;
          }
          try {
            const findResp = await fetchWithTimeout(
              `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(queryName)}`,
              { headers: { 'Authorization': `Bearer ${cfToken}` } },
              10000
            );
            const findData = await findResp.json();
            // Delete ALL records matching type+name (don't match content, it may have rotated)
            for (const rec of (findData.result || [])) {
              try {
                await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${rec.id}`, {
                  method: 'DELETE',
                  headers: { 'Authorization': `Bearer ${cfToken}` }
                }, 10000);
                cleanup.dns_deleted++;
              } catch (e) {
                cleanup.dns_errors.push(`Failed to delete ${type} ${name}: ${e.message}`);
              }
            }
          } catch (e) {
            cleanup.dns_errors.push(`Failed to find ${type} ${name}: ${e.message}`);
          }
        }

        // Delete CF Email Routing MX records (single query, delete all matching)
        try {
          const mxResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=MX&name=${domainName}`,
            { headers: { 'Authorization': `Bearer ${cfToken}` } },
            10000
          );
          const mxData = await mxResp.json();
          const cfMxRecords = (mxData.result || []).filter(r => r.content && r.content.includes('.mx.cloudflare.net'));
          for (const rec of cfMxRecords) {
            try {
              await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${rec.id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${cfToken}` }
              }, 10000);
              cleanup.dns_deleted++;
            } catch (e) {
              cleanup.dns_errors.push(`Failed to delete MX ${rec.content}: ${e.message}`);
            }
          }
        } catch (e) {
          cleanup.dns_errors.push(`Failed to query MX records: ${e.message}`);
        }

        // Delete CF Email Routing SPF TXT record (v=spf1 include:_spf.mx.cloudflare.net)
        try {
          const spfResp = await fetchWithTimeout(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=TXT&name=${domainName}`,
            { headers: { 'Authorization': `Bearer ${cfToken}` } },
            10000
          );
          const spfData = await spfResp.json();
          const spfRecords = (spfData.result || []).filter(r => r.content && r.content.includes('_spf.mx.cloudflare.net'));
          for (const rec of spfRecords) {
            try {
              await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${rec.id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${cfToken}` }
              }, 10000);
              cleanup.dns_deleted++;
            } catch (e) {
              cleanup.dns_errors.push(`Failed to delete SPF record: ${e.message}`);
            }
          }
        } catch (e) { /* skip */ }

        // Reset catch-all Email Routing rule (disable it instead of deleting)
        try {
          await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/email/routing/rules/catch_all`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              enabled: false,
              matchers: [{ type: 'all' }],
              actions: [{ type: 'drop' }]
            })
          }, 10000);
          cleanup.email_routing_deleted = true;
        } catch (e) {
          cleanup.dns_errors.push(`Failed to disable catch-all: ${e.message}`);
        }
      } else {
        cleanup.dns_errors.push('Could not find Cloudflare zone for domain: ' + domainName);
      }
    } catch (e) {
      cleanup.dns_errors.push('Cleanup error: ' + e.message);
    }
  }

  return json({ success: true, cleanup });
}

async function handleVerifyDomain(request, env, db, json) {
  const body = await request.json();
  const { domain_id, zone_id } = body;
  const domainProvider = await getSetting(db, 'domain_provider') || 'resend';

  if (domainProvider === 'cf') {
    // CF Email Service: check subdomain status
    const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
    if (!cfToken || !zone_id || !domain_id) return json({ error: 'Missing params' }, 400);
    try {
      const resp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zone_id}/email/sending/subdomains/${domain_id}`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } }
      );
      const data = await resp.json();
      const sub = data.result || {};
      return json({ success: true, domain: { id: sub.tag, name: sub.name, status: sub.enabled ? 'verified' : 'pending' }, records: [] });
    } catch (e) {
      return json({ success: false, error: e.message });
    }
  }

  // Resend: existing logic
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  if (!resendKey) return json({ error: 'Resend API key not configured' }, 400);
  const resp = await fetch(`https://api.resend.com/domains/${domain_id}/verify`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${resendKey}` }
  });
  const result = await resp.json();
  let records = [];
  try {
    const infoResp = await fetch(`https://api.resend.com/domains/${domain_id}`, {
      headers: { 'Authorization': `Bearer ${resendKey}` }
    });
    const infoData = await infoResp.json();
    records = (infoData.records || []).map(r => ({
      type: r.record_type || r.type,
      name: r.name,
      value: r.value || r.expected_value,
      status: r.status
    }));
  } catch (e) { /* ignore */ }
  return json({ success: resp.ok, domain: result, records });
}

async function handleGetDnsRecords(env, db, url, json) {
  const domain_id = url.searchParams.get('domain_id');
  const zone_id = url.searchParams.get('zone_id');
  const domainProvider = await getSetting(db, 'domain_provider') || 'resend';

  if (domainProvider === 'cf') {
    // CF Email Service: get subdomain DNS records and verify against actual DNS
    const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
    if (!cfToken || !zone_id || !domain_id) return json({ error: 'Missing params' }, 400);
    try {
      const resp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zone_id}/email/sending/subdomains/${domain_id}/dns`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } }
      );
      const data = await resp.json();
      const requiredRecords = data.result || [];

      // Fetch actual DNS records from the zone to compare status
      const actualDnsResp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?per_page=500`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } }
      );
      const actualDnsData = await actualDnsResp.json();
      const actualRecords = actualDnsData.result || [];

      // Build lookup set of actual records: "type|name|content"
      const actualSet = new Set();
      for (const r of actualRecords) {
        // Normalize: CF DNS API returns content without trailing dot, but email sending API may include it
        const content = (r.content || '').replace(/\.$/, '');
        actualSet.add(`${r.type}|${r.name}|${content}`);
      }

      // Check each required record against actual DNS
      const enrichedRecords = requiredRecords.map(r => {
        const content = (r.content || '').replace(/\.$/, '').replace(/^"|"$/g, '');
        const key = `${r.type}|${r.name}|${content}`;
        // For DMARC records, just check if any DMARC record exists at the same name
        // (policy value like p=none vs p=reject is a user preference, not a hard requirement)
        const isDmarc = r.name && r.name.startsWith('_dmarc.');
        let found = actualSet.has(key) || actualRecords.some(a =>
          a.type === r.type && a.name === r.name && (a.content || '').replace(/^"|"$/g, '').includes(content.slice(0, 40))
        );
        if (!found && isDmarc) {
          found = actualRecords.some(a => a.type === 'TXT' && a.name === r.name && (a.content || '').includes('v=DMARC1'));
        }
        return { ...r, status: found ? 'verified' : 'pending', record_type: r.type, value: r.content };
      });

      // Get the subdomain name for the response
      let domainName = '';
      try {
        const subResp = await fetchWithTimeout(
          `https://api.cloudflare.com/client/v4/zones/${zone_id}/email/sending/subdomains`,
          { headers: { 'Authorization': `Bearer ${cfToken}` } }
        );
        const subData = await subResp.json();
        const sub = (subData.result || []).find(s => s.tag === domain_id || s.id === domain_id);
        if (sub) domainName = sub.name;
      } catch (e) { /* ignore */ }

      return json({ domain: { name: domainName, records: enrichedRecords }, provider: 'cf' });
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  }

  // Resend: existing logic
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  if (!resendKey || !domain_id) return json({ error: 'Missing params' }, 400);
  const resp = await fetch(`https://api.resend.com/domains/${domain_id}`, {
    headers: { 'Authorization': `Bearer ${resendKey}` }
  });
  const result = await resp.json();
  // Strip overlapping domain parts from record names for display
  // e.g. Resend returns "resend._domainkey.niuma" for domain "niuma.qzz.io"
  // but in CF zone "niuma.qzz.io" the correct name is "resend._domainkey"
  if (result.name && result.records) {
    const domainName = result.name;
    const domainParts = domainName.split('.');
    result.records = result.records.map(r => {
      if (!r.name) return r;
      let cleaned = r.name;
      for (let i = domainParts.length; i >= 1; i--) {
        const suffix = '.' + domainParts.slice(0, i).join('.');
        if (cleaned.endsWith(suffix)) {
          cleaned = cleaned.slice(0, -suffix.length) || domainName;
          break;
        }
      }
      return { ...r, name: cleaned };
    });
  }
  return json({ domain: result });
}

// Manually trigger DNS auto-setup for an existing domain
async function handleAutoDns(request, env, db, json) {
  const { domain_id, domain_name, zone_id } = await request.json();
  const domainProvider = await getSetting(db, 'domain_provider') || 'resend';
  const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
  if (!cfToken) return json({ error: 'Cloudflare API token not configured' }, 400);

  if (domainProvider === 'cf') {
    // CF Email Service auto-creates DNS records, so just return success
    return json({ success: true, results: [{ type: 'info', name: 'CF Email Service', status: 'auto', message: 'DNS records auto-managed by CF Email Service' }] });
  }

  // Resend: existing logic
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  if (!resendKey) return json({ error: 'Resend API key not configured' }, 400);
  if (!domain_id) return json({ error: 'domain_id required' }, 400);

  const results = await autoCreateDnsRecords(cfToken, resendKey, domain_id, domain_name || '', zone_id || null);
  // Auto-trigger verification after DNS setup
  try {
    await fetch(`https://api.resend.com/domains/${domain_id}/verify`, {
      method: 'POST', headers: { 'Authorization': `Bearer ${resendKey}` }
    });
  } catch (e) { /* ignore */ }
  return json({ success: true, results });
}
async function handleGetSettings(db, env, json) {
  const settings = await getAllSettings(db);
  // Merge env vars as fallback — these are set via wrangler.toml / GitHub Secrets
  const envFallbacks = {
    resend_api_key: env.RESEND_API_KEY,
    cf_api_token: env.CF_API_TOKEN_VAR,
  };
  for (const [key, envVal] of Object.entries(envFallbacks)) {
    if (!settings[key] && envVal) {
      settings[key] = envVal;
    }
  }
  // Mask sensitive values
  const masked = { ...settings };
  if (masked.resend_api_key) masked.resend_api_key = masked.resend_api_key.substring(0, 8) + '***';
  if (masked.cf_api_token) masked.cf_api_token = masked.cf_api_token.substring(0, 8) + '***';
  if (masked.tg_bot_token) masked.tg_bot_token = masked.tg_bot_token.substring(0, 8) + '***';
  if (masked.resend_webhook_secret) masked.resend_webhook_secret = masked.resend_webhook_secret.substring(0, 8) + '***';
  return json({ settings: masked, raw_keys: Object.keys(settings) });
}

async function handleSaveSettings(request, db, json) {
  const { settings } = await request.json();
  const allowedKeys = [
    'resend_api_key', 'cf_api_token',
    'domain_provider',
    'tg_bot_token', 'tg_chat_id', 'tg_topic_id',
    'forward_to',
    'auto_create_enabled', 'auto_create_min_length', 'auto_create_max_length',
    'webhook_url',
    'send_method',
    'resend_day_limit', 'resend_month_limit',
    'cf_day_limit', 'cf_month_limit',
    'resend_webhook_secret',
  ];
  for (const [key, value] of Object.entries(settings)) {
    if (!allowedKeys.includes(key)) continue;
    if (value === '' || value === null || value === undefined) {
      await db.prepare('DELETE FROM settings WHERE key = ?').bind(key).run();
    } else {
      // Don't overwrite masked values
      if (typeof value === 'string' && value.includes('***')) continue;
      await setSetting(db, key, value);
    }
  }
  return json({ success: true });
}

// ---- Email Routing Auto-Setup ----
// Check email routing status for a domain
async function handleEmailRoutingStatus(env, db, url, json) {
  const domain = url.searchParams.get('domain');
  const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
  if (!cfToken) return json({ error: 'Cloudflare API token not configured' }, 400);
  if (!domain) return json({ error: 'domain parameter required' }, 400);

  const zoneIdParam = url.searchParams.get('zone_id');
  try {
    let zoneId = zoneIdParam;
    let zoneName = domain;
    if (!zoneId) {
      // Try exact domain match first, then try parent domains for subdomains
      let zones = [];
      const candidates = [domain];
      const parts = domain.split('.');
      // Generate parent domain candidates (e.g. for "sub.example.com" try "example.com")
      for (let i = 1; i < parts.length - 1; i++) {
        candidates.push(parts.slice(i).join('.'));
      }
      for (const candidate of candidates) {
        const zoneResp = await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones?name=${candidate}&status=active`, {
          headers: { 'Authorization': `Bearer ${cfToken}` }
        }, 10000);
        const zoneData = await zoneResp.json();
        zones = zoneData.result || [];
        if (zones.length) {
          zoneName = candidate;
          break;
        }
      }
      if (!zones.length) return json({ enabled: false, error: 'Zone not found' });
      zoneId = zones[0].id;
    }

    // Check catch-all rule (use dedicated endpoint) — this is the real indicator of routing status
    let catchAllConfigured = false;
    let catchAllWorker = null;
    let catchAllActionType = null;
    let catchAllError = null;
    try {
      const catchAllResp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/email/routing/rules/catch_all`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } },
        10000
      );
      const catchAllData = await catchAllResp.json();
      if (!catchAllData.success) {
        catchAllError = (catchAllData.errors || []).map(e => e.message).join(', ') || 'API error ' + catchAllResp.status;
      } else {
        const catchAll = catchAllData.result;
        if (catchAll && catchAll.enabled) {
          const actions = catchAll.actions || [];
          const workerAction = actions.find(a => a.type === 'worker');
          if (workerAction) {
            catchAllConfigured = true;
            catchAllWorker = workerAction.value?.[0] || null;
            catchAllActionType = 'worker';
          } else if (actions.length > 0) {
            // Catch-all is enabled but not pointing to a worker (e.g. forward/drop)
            catchAllActionType = actions[0].type;
          }
        }
      }
    } catch (e) { catchAllError = e.message; }

    // Check MX records for email routing (use zone name, not subdomain)
    let mxConfigured = false;
    let mxError = null;
    try {
      // MX records are on the zone root, not on subdomains
      const mxCheckName = zoneName || domain;
      const mxResp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=MX&name=${mxCheckName}`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } },
        10000
      );
      const mxData = await mxResp.json();
      if (!mxData.success) {
        mxError = (mxData.errors || []).map(e => e.message).join(', ') || 'API error ' + mxResp.status;
      } else {
        const cfMxRecords = (mxData.result || []).filter(r => r.content && r.content.includes('.mx.cloudflare.net'));
        mxConfigured = cfMxRecords.length >= 3;
      }
    } catch (e) { mxError = e.message; }

    // Infer enabled from catch-all + MX (no extra permission needed)
    const enabled = catchAllConfigured && mxConfigured;

    return json({
      enabled,
      catch_all: catchAllConfigured,
      catch_all_worker: catchAllWorker,
      catch_all_action_type: catchAllActionType,
      catch_all_error: catchAllError,
      mx_configured: mxConfigured,
      mx_error: mxError,
      zone_id: zoneId
    });
  } catch (e) {
    return json({ enabled: false, error: e.message }, 500);
  }
}

async function handleSetupEmailRouting(request, env, db, json) {
  const { domain, zone_id } = await request.json();
  const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
  if (!cfToken) return json({ error: 'Cloudflare API token not configured' }, 400);
  if (!domain) return json({ error: 'Domain is required' }, 400);

  // Auto-detect worker name: env var > wrangler.toml name > fallback
  const workerName = env.WORKER_NAME || 'mailhub';
  const results = await autoSetupEmailRouting(cfToken, domain, workerName, zone_id || null);
  return json({ success: true, results });
}

async function autoSetupEmailRouting(cfToken, domain, workerName, zoneIdParam) {
  const results = [];
  try {
    // Use zone_id directly if provided, otherwise fallback to lookup
    let zoneId = zoneIdParam;
    if (!zoneId) {
      const zoneResp = await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones?name=${domain}&status=active`, {
        headers: { 'Authorization': `Bearer ${cfToken}` }
      });
      const zoneData = await zoneResp.json();
      const zones = zoneData.result || [];
      if (!zones.length) {
        return [{ step: 'find_zone', status: 'error', message: `Zone not found for ${domain}` }];
      }
      zoneId = zones[0].id;
    }

    // Skip the deprecated enable check entirely — if catch-all and MX work, routing is active
    // The POST /email/routing/enable endpoint is deprecated and GET /email/routing
    // requires Email Routing Addresses:Read permission most tokens don't have.
    // Just proceed to configure MX + catch-all directly.

    // Create MX records for CF Email Routing
    const mxRecords = [
      { type: 'MX', name: domain, content: 'route1.mx.cloudflare.net', priority: 69, ttl: 1 },
      { type: 'MX', name: domain, content: 'route2.mx.cloudflare.net', priority: 12, ttl: 1 },
      { type: 'MX', name: domain, content: 'route3.mx.cloudflare.net', priority: 41, ttl: 1 },
    ];
    for (const mx of mxRecords) {
      try {
        const existResp = await fetchWithTimeout(
          `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=MX&name=${mx.name}`,
          { headers: { 'Authorization': `Bearer ${cfToken}` } }
        );
        const existData = await existResp.json();
        const existing = (existData.result || []).find(r => r.content === mx.content);
        if (existing) {
          results.push({ step: 'mx_record', content: mx.content, status: 'exists' });
          continue;
        }
        const createResp = await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(mx)
        });
        const createData = await createResp.json();
        results.push({ step: 'mx_record', content: mx.content, status: createData.success ? 'created' : 'failed', error: createData.success ? null : (createData.errors?.[0]?.message || '') });
      } catch (e) {
        results.push({ step: 'mx_record', content: mx.content, status: 'error', error: e.message });
      }
    }

    // Configure catch-all rule pointing to the Worker (use dedicated catch_all endpoint)
    try {
      // First check current catch-all rule
      const getCatchAllResp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/email/routing/rules/catch_all`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } }
      );
      const getCatchAllData = await getCatchAllResp.json();
      const currentCatchAll = getCatchAllData.result;
      const alreadyPointsToWorker = currentCatchAll &&
        currentCatchAll.enabled &&
        (currentCatchAll.actions || []).some(a => a.type === 'worker' && Array.isArray(a.value) && a.value.some(v => v === workerName));

      if (alreadyPointsToWorker) {
        results.push({ step: 'catch_all_rule', status: 'exists' });
      } else {
        // Update catch-all rule via dedicated endpoint
        const updateResp = await fetchWithTimeout(
          `https://api.cloudflare.com/client/v4/zones/${zoneId}/email/routing/rules/catch_all`,
          {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              enabled: true,
              matchers: [{ type: 'all' }],
              actions: [{ type: 'worker', value: [workerName] }]
            })
          }
        );
        const updateData = await updateResp.json();
        if (updateData.success) {
          results.push({ step: 'catch_all_rule', status: 'updated' });
        } else {
          results.push({
            step: 'catch_all_rule', status: 'failed',
            error: updateData.errors?.[0]?.message || JSON.stringify(updateData.errors || 'Unknown error')
          });
        }
      }
    } catch (e) {
      results.push({ step: 'catch_all_rule', status: 'error', error: e.message });
    }

    // Create TXT record for SPF (email routing)
    try {
      const spfResp = await fetchWithTimeout(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=TXT&name=${domain}`,
        { headers: { 'Authorization': `Bearer ${cfToken}` } }
      );
      const spfData = await spfResp.json();
      const existingSpf = (spfData.result || []).find(r => r.content && r.content.includes('v=spf1'));
      if (!existingSpf) {
        const createSpfResp = await fetchWithTimeout(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'TXT', name: domain, content: 'v=spf1 include:_spf.mx.cloudflare.net ~all', ttl: 1 })
        });
        const createSpfData = await createSpfResp.json();
        results.push({ step: 'spf_record', status: createSpfData.success ? 'created' : 'failed', error: createSpfData.success ? null : (createSpfData.errors?.[0]?.message || '') });
      } else {
        results.push({ step: 'spf_record', status: 'exists' });
      }
    } catch (e) {
      results.push({ step: 'spf_record', status: 'error', error: e.message });
    }
  } catch (e) {
    results.push({ step: 'general', status: 'error', message: e.message });
  }
  return results;
}

// ---- R2 Storage Helpers ----

// Build simple EML format from email parts
function buildSimpleEml(from, to, subject, html, text) {
  const boundary = 'boundary_' + Date.now();
  const dateStr = new Date().toUTCString();
  let eml = `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nDate: ${dateStr}\r\n`;
  eml += `MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n`;
  if (text) {
    eml += `--${boundary}\r\nContent-Type: text/plain; charset="utf-8"\r\n\r\n${text}\r\n`;
  }
  if (html) {
    eml += `--${boundary}\r\nContent-Type: text/html; charset="utf-8"\r\n\r\n${html}\r\n`;
  }
  eml += `--${boundary}--\r\n`;
  return eml;
}

// Clean up R2 files for a message (EML + attachments)
async function cleanupMessageR2(db, env, messageId) {
  if (!env.R2) return;
  try {
    // Delete EML
    const msg = await db.prepare('SELECT eml_r2_key FROM messages WHERE id = ?').bind(messageId).first();
    if (msg && msg.eml_r2_key) {
      await env.R2.delete(msg.eml_r2_key);
    }
    // Delete attachments
    const atts = await db.prepare('SELECT r2_key FROM attachments WHERE message_id = ?').bind(messageId).all();
    for (const att of atts.results) {
      if (att.r2_key) await env.R2.delete(att.r2_key);
    }
  } catch (e) { console.error('R2 cleanup error:', e); }
}

// Download attachment from R2
async function handleDownloadAttachment(path, db, env, corsHeaders) {
  const id = parseInt(path.split('/')[3]);
  const att = await db.prepare('SELECT * FROM attachments WHERE id = ?').bind(id).first();
  if (!att) return new Response('Not found', { status: 404, headers: corsHeaders });

  // Try R2 first
  if (att.r2_key && env.R2) {
    const obj = await env.R2.get(att.r2_key);
    if (obj) {
      const headers = {
        ...corsHeaders,
        'Content-Type': att.content_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${encodeURIComponent(att.filename)}"`,
      };
      if (obj.size) headers['Content-Length'] = String(obj.size);
      return new Response(obj.body, { headers });
    }
  }

  // Fallback to D1 content
  if (att.content) {
    let body;
    try {
      body = Uint8Array.from(atob(att.content), c => c.charCodeAt(0));
    } catch {
      body = new TextEncoder().encode(att.content);
    }
    return new Response(body, {
      headers: {
        ...corsHeaders,
        'Content-Type': att.content_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${encodeURIComponent(att.filename)}"`,
        'Content-Length': String(body.byteLength),
      }
    });
  }

  return new Response('File not found', { status: 404, headers: corsHeaders });
}

// Download sent attachment from R2
async function handleDownloadSentAttachment(path, db, env, corsHeaders) {
  const id = parseInt(path.split('/')[3]);
  let att;
  try {
    att = await db.prepare('SELECT * FROM sent_attachments WHERE id = ?').bind(id).first();
  } catch (e) { return new Response('Not found', { status: 404, headers: corsHeaders }); }
  if (!att) return new Response('Not found', { status: 404, headers: corsHeaders });

  if (att.r2_key && env.R2) {
    const obj = await env.R2.get(att.r2_key);
    if (obj) {
      return new Response(obj.body, {
        headers: {
          ...corsHeaders,
          'Content-Type': att.content_type || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(att.filename)}"`,
          'Content-Length': att.size || '',
        }
      });
    }
  }

  return new Response('File not found', { status: 404, headers: corsHeaders });
}

// Download raw EML from R2
async function handleDownloadEml(path, db, env, corsHeaders) {
  const id = parseInt(path.split('/')[3]);
  const msg = await db.prepare('SELECT eml_r2_key, sender, to_addr, subject, html_content, text_content FROM messages WHERE id = ?').bind(id).first();
  if (!msg) return new Response('Not found', { status: 404, headers: corsHeaders });

  // Try R2 first
  if (msg.eml_r2_key && env.R2) {
    const obj = await env.R2.get(msg.eml_r2_key);
    if (obj) {
      return new Response(obj.body, {
        headers: {
          ...corsHeaders,
          'Content-Type': 'message/rfc822',
          'Content-Disposition': `attachment; filename="message-${id}.eml"`,
        }
      });
    }
  }

  // Fallback: build EML from D1 content
  const eml = buildSimpleEml(msg.sender, msg.to_addr, msg.subject, msg.html_content, msg.text_content);
  return new Response(eml, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'message/rfc822',
      'Content-Disposition': `attachment; filename="message-${id}.eml"`,
    }
  });
}

// ---- Stats ----
async function handleFolderCounts(db, url, json) {
  const mailboxId = url.searchParams.get('mailbox_id');
  if (mailboxId) {
    const mid = parseInt(mailboxId);
    const mbx = await db.prepare('SELECT address FROM mailboxes WHERE id = ?').bind(mid).first();
    if (!mbx) return json({ error: 'Not found' }, 404);
    const addr = mbx.address;
    const [inboxTotal, inboxUnread, sentTotal, favInbox, trashInbox, trashSent, sentFailed] = await Promise.all([
      db.prepare('SELECT COUNT(*) as c FROM messages WHERE mailbox_id = ? AND (is_deleted = 0 OR is_deleted IS NULL)').bind(mid).first(),
      db.prepare('SELECT COUNT(*) as c FROM messages WHERE mailbox_id = ? AND is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)').bind(mid).first(),
      db.prepare('SELECT COUNT(*) as c FROM sent_emails WHERE from_addr = ? AND (is_deleted = 0 OR is_deleted IS NULL)').bind(addr).first().catch(() => ({ c: 0 })),
      db.prepare('SELECT COUNT(*) as c FROM messages WHERE mailbox_id = ? AND is_favorite = 1 AND (is_deleted = 0 OR is_deleted IS NULL)').bind(mid).first().catch(() => ({ c: 0 })),
      db.prepare('SELECT COUNT(*) as c FROM messages WHERE mailbox_id = ? AND is_deleted = 1').bind(mid).first(),
      db.prepare('SELECT COUNT(*) as c FROM sent_emails WHERE from_addr = ? AND is_deleted = 1').bind(addr).first().catch(() => ({ c: 0 })),
      db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE from_addr = ? AND status IN ('bounced','complained') AND (is_deleted = 0 OR is_deleted IS NULL)").bind(addr).first().catch(() => ({ c: 0 })),
    ]);
    return json({
      inbox_total: inboxTotal.c || 0,
      inbox_unread: inboxUnread.c || 0,
      sent_total: sentTotal.c || 0,
      fav_total: favInbox.c || 0,
      trash_total: (trashInbox.c || 0) + (trashSent.c || 0),
      sent_failed: sentFailed.c || 0,
    });
  }
  // Global (all mailboxes)
  const [inboxTotal, inboxUnread, sentTotal, favInbox, favSent, trash, sentFailed] = await Promise.all([
    db.prepare('SELECT COUNT(*) as c FROM messages WHERE (is_deleted = 0 OR is_deleted IS NULL)').first(),
    db.prepare('SELECT COUNT(*) as c FROM messages WHERE is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)').first(),
    db.prepare('SELECT COUNT(*) as c FROM sent_emails WHERE (is_deleted = 0 OR is_deleted IS NULL)').first(),
    db.prepare('SELECT COUNT(*) as c FROM messages WHERE is_favorite = 1 AND (is_deleted = 0 OR is_deleted IS NULL)').first().catch(() => ({ c: 0 })),
    db.prepare('SELECT COUNT(*) as c FROM sent_emails WHERE is_favorite = 1 AND (is_deleted = 0 OR is_deleted IS NULL)').first().catch(() => ({ c: 0 })),
    db.prepare('SELECT (SELECT COUNT(*) FROM messages WHERE is_deleted = 1) + (SELECT COUNT(*) FROM sent_emails WHERE is_deleted = 1) as c').first(),
    db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE status IN ('bounced','complained') AND (is_deleted = 0 OR is_deleted IS NULL)").first(),
  ]);
  return json({
    inbox_total: inboxTotal.c || 0,
    inbox_unread: inboxUnread.c || 0,
    sent_total: sentTotal.c || 0,
    fav_total: (favInbox.c || 0) + (favSent.c || 0),
    trash_total: trash.c || 0,
    sent_failed: sentFailed.c || 0,
  });
}

async function handleGetStats(db, env, json) {
  const resendKey = await getSetting(db, 'resend_api_key') || env.RESEND_API_KEY;
  const cfToken = await getSetting(db, 'cf_api_token') || env.CF_API_TOKEN_VAR;
  const sendMethod = await getSetting(db, 'send_method') || 'auto';

  // DB-based sent counts (accurate regardless of API limitations)
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const thisMonth = new Date().toISOString().slice(0, 7); // YYYY-MM

  // Read user-configured quota limits (empty string means unlimited)
  const [resendDayLimitSetting, resendMonthLimitSetting, cfDayLimitSetting, cfMonthLimitSetting,
         sentTodayResend, sentMonthResend, sentTodayCf, sentMonthCf] = await Promise.all([
    getSetting(db, 'resend_day_limit').catch(() => null),
    getSetting(db, 'resend_month_limit').catch(() => null),
    getSetting(db, 'cf_day_limit').catch(() => null),
    getSetting(db, 'cf_month_limit').catch(() => null),
    db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE date(created_at) = ? AND send_provider = 'resend' AND (is_deleted = 0 OR is_deleted IS NULL)").bind(today).first().catch(() => ({ c: 0 })),
    db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE created_at LIKE ? AND send_provider = 'resend' AND (is_deleted = 0 OR is_deleted IS NULL)").bind(thisMonth + '%').first().catch(() => ({ c: 0 })),
    db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE date(created_at) = ? AND (send_provider = 'cf_email_service' OR send_provider = 'cf_native') AND (is_deleted = 0 OR is_deleted IS NULL)").bind(today).first().catch(() => ({ c: 0 })),
    db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE created_at LIKE ? AND (send_provider = 'cf_email_service' OR send_provider = 'cf_native') AND (is_deleted = 0 OR is_deleted IS NULL)").bind(thisMonth + '%').first().catch(() => ({ c: 0 })),
  ]);

  // null/empty = unlimited (no limit bar shown); number = limit
  const parseLimit = (v) => (v === null || v === undefined || v === '') ? null : parseInt(v, 10);
  const resendDayLimit   = parseLimit(resendDayLimitSetting);
  const resendMonthLimit = parseLimit(resendMonthLimitSetting);
  const cfDayLimit       = parseLimit(cfDayLimitSetting);
  const cfMonthLimit     = parseLimit(cfMonthLimitSetting);

  const resendConfigured = !!resendKey;
  const cfConfigured = !!(cfToken || env.SEND_EMAIL);

  // Always return both quota objects so the frontend can always display them.
  // If service is not configured, counts stay at 0.
  const quota = {
    resend: {
      configured:  resendConfigured,
      status:      resendConfigured ? 'Active' : 'Not configured',
      sent_today:  resendConfigured ? (sentTodayResend.c  || 0) : 0,
      sent_month:  resendConfigured ? (sentMonthResend.c  || 0) : 0,
      day_limit:   resendDayLimit,
      month_limit: resendMonthLimit,
    },
    cf: {
      configured:  cfConfigured,
      status:      cfConfigured ? 'Active' : 'Not configured',
      sent_today:  cfConfigured ? (sentTodayCf.c  || 0) : 0,
      sent_month:  cfConfigured ? (sentMonthCf.c  || 0) : 0,
      day_limit:   cfDayLimit,
      month_limit: cfMonthLimit,
    },
  };

  const [inbox, unread, sent, mailboxes, attCount, trashCount, sentFailed] = await Promise.all([
    db.prepare('SELECT COUNT(*) as c FROM messages WHERE (is_deleted = 0 OR is_deleted IS NULL)').first(),
    db.prepare('SELECT COUNT(*) as c FROM messages WHERE is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)').first(),
    db.prepare('SELECT COUNT(*) as c FROM sent_emails WHERE (is_deleted = 0 OR is_deleted IS NULL)').first(),
    db.prepare('SELECT COUNT(*) as c FROM mailboxes').first(),
    db.prepare("SELECT COUNT(*) as c FROM attachments WHERE r2_key != '' AND r2_key IS NOT NULL").first(),
    db.prepare('SELECT (SELECT COUNT(*) FROM messages WHERE is_deleted = 1) + (SELECT COUNT(*) FROM sent_emails WHERE is_deleted = 1) as c').first(),
    db.prepare("SELECT COUNT(*) as c FROM sent_emails WHERE status IN ('bounced','complained') AND (is_deleted = 0 OR is_deleted IS NULL)").first(),
  ]);
  return json({
    inbox_total: inbox.c,
    inbox_unread: unread.c,
    sent_total: sent.c,
    sent_failed: sentFailed.c || 0,
    mailboxes_total: mailboxes.c,
    r2_files: attCount.c,
    trash_total: trashCount.c || 0,
    quota: quota,
    send_method: sendMethod
  });
}

async function handleGetUnreadCount(db, json) {
  const result = await db.prepare('SELECT COUNT(*) as c FROM messages WHERE is_read = 0 AND (is_deleted = 0 OR is_deleted IS NULL)').first();
  return json({ unread: result.c });
}
