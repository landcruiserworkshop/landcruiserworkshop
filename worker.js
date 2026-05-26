/**
 * Land Cruiser Workshop — Auth Worker
 * Handles: signup, verify, login, logout, session, download, settings,
 *          delete account, email change, resend verify, rate limiting,
 *          manual requests
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://landcruiserworkshop.com',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Credentials': 'true',
};

const SESSION_TTL = 60 * 60 * 24 * 30; // 30 days
const RATE_LIMIT_WINDOW = 60 * 15; // 15 minutes
const RATE_LIMIT_MAX = 10; // max login attempts per window

// ── Crypto helpers ──────────────────────────────────────────────────────────

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const newHashHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
  return newHashHex === hashHex;
}

function generateToken(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSessionId() { return crypto.randomUUID(); }

// ── Rate limiting ───────────────────────────────────────────────────────────

async function checkRateLimit(env, key) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  // Clean old attempts and count recent ones
  await env.DB.prepare(
    'DELETE FROM rate_limits WHERE key = ? AND timestamp < ?'
  ).bind(key, windowStart).run();
  
  const count = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM rate_limits WHERE key = ?'
  ).bind(key).first();
  
  if (count.cnt >= RATE_LIMIT_MAX) return false;
  
  await env.DB.prepare(
    'INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)'
  ).bind(key, now).run();
  
  return true;
}

// ── Email helpers ───────────────────────────────────────────────────────────

async function sendEmail(to, subject, html, resendApiKey) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${resendApiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Land Cruiser Workshop <noreply@landcruiserworkshop.com>',
      to, subject, html,
    }),
  });
  return res.ok;
}

function emailTemplate(content) {
  return `
    <div style="font-family:'Courier New',monospace;max-width:600px;margin:0 auto;background:#f5f0e8;padding:40px;">
      <h1 style="color:#2a2118;font-size:24px;border-bottom:3px solid #2a2118;padding-bottom:16px;">Land Cruiser Workshop</h1>
      ${content}
      <p style="color:#6b5a3e;font-size:12px;margin-top:32px;border-top:1px solid #c4b49a;padding-top:16px;">
        landcruiserworkshop.com — Toyota Land Cruiser Factory Service Manual Archive
      </p>
    </div>
  `;
}

function btnLink(url, text) {
  return `<a href="${url}" style="display:inline-block;margin:24px 0;padding:14px 28px;background:#2a2118;color:#f5f0e8;text-decoration:none;font-family:'Courier New',monospace;font-size:14px;letter-spacing:0.1em;text-transform:uppercase;">${text}</a>`;
}

async function sendVerificationEmail(email, token, siteUrl, key) {
  return sendEmail(email, 'Verify your email — Land Cruiser Workshop', emailTemplate(`
    <p style="color:#2a2118;font-size:16px;line-height:1.6;">Thanks for signing up. Click below to verify your email and access the factory service manual archive.</p>
    ${btnLink(`${siteUrl}/api/auth/verify?token=${token}`, 'Verify Email')}
    <p style="color:#6b5a3e;font-size:13px;">If you didn't create an account, ignore this email.</p>
  `), key);
}

async function sendPasswordResetEmail(email, token, siteUrl, key) {
  return sendEmail(email, 'Reset your password — Land Cruiser Workshop', emailTemplate(`
    <p style="color:#2a2118;font-size:16px;line-height:1.6;">You requested a password reset. Click below — expires in 1 hour.</p>
    ${btnLink(`${siteUrl}?reset=${token}`, 'Reset Password')}
    <p style="color:#6b5a3e;font-size:13px;">If you didn't request this, ignore this email.</p>
  `), key);
}

async function sendEmailChangeEmail(email, token, siteUrl, key) {
  return sendEmail(email, 'Confirm your new email — Land Cruiser Workshop', emailTemplate(`
    <p style="color:#2a2118;font-size:16px;line-height:1.6;">Click below to confirm your new email address.</p>
    ${btnLink(`${siteUrl}/api/auth/confirm-email?token=${token}`, 'Confirm New Email')}
    <p style="color:#6b5a3e;font-size:13px;">If you didn't request this, ignore this email.</p>
  `), key);
}

async function sendDeleteConfirmEmail(email, token, siteUrl, key) {
  return sendEmail(email, 'Confirm account deletion — Land Cruiser Workshop', emailTemplate(`
    <p style="color:#2a2118;font-size:16px;line-height:1.6;">You requested to delete your account. Click below to confirm — this action is permanent and cannot be undone.</p>
    ${btnLink(`${siteUrl}/api/auth/confirm-delete?token=${token}`, 'Delete My Account')}
    <p style="color:#6b5a3e;font-size:13px;">If you didn't request this, ignore this email — your account is safe.</p>
  `), key);
}

// ── Session helper ──────────────────────────────────────────────────────────

async function getSession(request, env) {
  const sessionId = getSessionCookie(request);
  if (!sessionId) return null;
  const session = await env.DB.prepare(
    'SELECT s.user_id, s.expires_at, u.email, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?'
  ).bind(sessionId).first();
  if (!session || session.expires_at < Math.floor(Date.now() / 1000)) return null;
  return session;
}

// ── Route handlers ──────────────────────────────────────────────────────────

async function handleSignup(request, env) {
  const { username, email, password, series_interest, mailing_list } = await request.json();

  if (!username || !email || !password) return json({ error: 'Username, email and password are required' }, 400);
  if (username.length < 3 || username.length > 30) return json({ error: 'Username must be between 3 and 30 characters' }, 400);
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return json({ error: 'Username can only contain letters, numbers, underscores and hyphens' }, 400);
  if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Invalid email address' }, 400);

  const existingUsername = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existingUsername) return json({ error: 'Username is already taken' }, 409);

  const existingEmail = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existingEmail) return json({ error: 'An account with this email already exists' }, 409);

  const password_hash = await hashPassword(password);
  const verify_token = generateToken();

  await env.DB.prepare(
    'INSERT INTO users (username, email, password_hash, verify_token, series_interest, mailing_list) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(username, email.toLowerCase(), password_hash, verify_token, series_interest || null, mailing_list ? 1 : 0).run();

  await sendVerificationEmail(email, verify_token, env.SITE_URL, env.RESEND_API_KEY);
  return json({ success: true, message: 'Check your email to verify your account' });
}

async function handleVerify(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  if (!token) return Response.redirect(`${env.SITE_URL}?verified=invalid`, 302);

  const user = await env.DB.prepare('SELECT id FROM users WHERE verify_token = ?').bind(token).first();
  if (!user) return Response.redirect(`${env.SITE_URL}?verified=invalid`, 302);

  await env.DB.prepare('UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?').bind(user.id).run();

  const sessionId = generateSessionId();
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL;
  await env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(sessionId, user.id, expiresAt).run();

  const response = Response.redirect(`${env.SITE_URL}?verified=success`, 302);
  return setSessionCookie(response, sessionId);
}

async function handleResendVerify(request, env) {
  const { email } = await request.json();
  if (!email) return json({ error: 'Email required' }, 400);

  const allowed = await checkRateLimit(env, `resend:${email.toLowerCase()}`);
  if (!allowed) return json({ error: 'Too many requests. Please wait 15 minutes.' }, 429);

  const user = await env.DB.prepare('SELECT id, verified, verify_token FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (user && !user.verified) {
    const token = user.verify_token || generateToken();
    if (!user.verify_token) {
      await env.DB.prepare('UPDATE users SET verify_token = ? WHERE id = ?').bind(token, user.id).run();
    }
    await sendVerificationEmail(email, token, env.SITE_URL, env.RESEND_API_KEY);
  }
  return json({ success: true, message: 'If an unverified account exists, a new link has been sent' });
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return json({ error: 'Email/username and password are required' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowed = await checkRateLimit(env, `login:${ip}`);
  if (!allowed) return json({ error: 'Too many login attempts. Please wait 15 minutes.' }, 429);

  const user = await env.DB.prepare(
    'SELECT id, password_hash, verified FROM users WHERE email = ? OR username = ?'
  ).bind(email.toLowerCase(), email).first();

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return json({ error: 'Invalid email/username or password' }, 401);
  }
  if (!user.verified) return json({ error: 'Please verify your email before logging in' }, 403);

  const sessionId = generateSessionId();
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL;
  await env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(sessionId, user.id, expiresAt).run();
  await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(Math.floor(Date.now() / 1000), user.id).run();

  const response = json({ success: true });
  return setSessionCookie(response, sessionId);
}

async function handleLogout(request, env) {
  const sessionId = getSessionCookie(request);
  if (sessionId) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
  const response = json({ success: true });
  return clearSessionCookie(response);
}

async function handleSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ authenticated: false });
  return json({ authenticated: true, email: session.email, username: session.username });
}

async function handleGetSettings(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const user = await env.DB.prepare('SELECT series_interest, mailing_list FROM users WHERE id = ?').bind(session.user_id).first();
  return json({ series_interest: user.series_interest || '', mailing_list: user.mailing_list === 1 });
}

async function handleUpdateSettings(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const { series_interest, mailing_list } = await request.json();
  await env.DB.prepare('UPDATE users SET series_interest = ?, mailing_list = ? WHERE id = ?')
    .bind(series_interest || null, mailing_list ? 1 : 0, session.user_id).run();
  return json({ success: true });
}

async function handleChangePassword(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);

  const { current_password, new_password } = await request.json();
  if (!current_password || !new_password) return json({ error: 'Both passwords required' }, 400);
  if (new_password.length < 8) return json({ error: 'New password must be at least 8 characters' }, 400);

  const user = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(session.user_id).first();
  if (!await verifyPassword(current_password, user.password_hash)) return json({ error: 'Current password is incorrect' }, 401);

  const new_hash = await hashPassword(new_password);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(new_hash, session.user_id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').bind(session.user_id, getSessionCookie(request)).run();
  return json({ success: true });
}

async function handleChangeEmail(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);

  const { new_email, password } = await request.json();
  if (!new_email || !password) return json({ error: 'New email and password required' }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(new_email)) return json({ error: 'Invalid email address' }, 400);

  const user = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(session.user_id).first();
  if (!await verifyPassword(password, user.password_hash)) return json({ error: 'Password is incorrect' }, 401);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(new_email.toLowerCase()).first();
  if (existing) return json({ error: 'Email is already in use' }, 409);

  const token = generateToken();
  await env.DB.prepare('UPDATE users SET pending_email = ?, email_change_token = ? WHERE id = ?')
    .bind(new_email.toLowerCase(), token, session.user_id).run();

  await sendEmailChangeEmail(new_email, token, env.SITE_URL, env.RESEND_API_KEY);
  return json({ success: true, message: 'Check your new email address for a confirmation link' });
}

async function handleConfirmEmail(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  if (!token) return Response.redirect(`${env.SITE_URL}?email_change=invalid`, 302);

  const user = await env.DB.prepare('SELECT id, pending_email FROM users WHERE email_change_token = ?').bind(token).first();
  if (!user || !user.pending_email) return Response.redirect(`${env.SITE_URL}?email_change=invalid`, 302);

  await env.DB.prepare('UPDATE users SET email = ?, pending_email = NULL, email_change_token = NULL WHERE id = ?')
    .bind(user.pending_email, user.id).run();

  return Response.redirect(`${env.SITE_URL}?email_change=success`, 302);
}

async function handleRequestDelete(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);

  const token = generateToken();
  await env.DB.prepare('UPDATE users SET delete_token = ?, delete_token_expires = ? WHERE id = ?')
    .bind(token, Math.floor(Date.now() / 1000) + 3600, session.user_id).run();

  await sendDeleteConfirmEmail(session.email, token, env.SITE_URL, env.RESEND_API_KEY);
  return json({ success: true, message: 'Check your email to confirm account deletion' });
}

async function handleConfirmDelete(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  if (!token) return Response.redirect(`${env.SITE_URL}?deleted=invalid`, 302);

  const user = await env.DB.prepare(
    'SELECT id, delete_token_expires FROM users WHERE delete_token = ?'
  ).bind(token).first();

  if (!user || user.delete_token_expires < Math.floor(Date.now() / 1000)) {
    return Response.redirect(`${env.SITE_URL}?deleted=invalid`, 302);
  }

  // Delete all user data
  await env.DB.prepare('DELETE FROM downloads WHERE user_id = ?').bind(user.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();

  const response = Response.redirect(`${env.SITE_URL}?deleted=success`, 302);
  return clearSessionCookie(response);
}

async function handleDownload(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);

  const { manual_code, manual_title } = await request.json();
  if (!manual_code) return json({ error: 'Manual code required' }, 400);

  await env.DB.prepare('INSERT INTO downloads (user_id, manual_code, manual_title) VALUES (?, ?, ?)')
    .bind(session.user_id, manual_code, manual_title || null).run();

  return json({ url: `https://files.landcruiserworkshop.com/manuals/${manual_code}.pdf` });
}

async function handleRequestManual(request, env) {
  const { manual_code, manual_title, notes, email } = await request.json();
  if (!manual_code) return json({ error: 'Manual code required' }, 400);

  const session = await getSession(request, env);
  const user_id = session ? session.user_id : null;

  await env.DB.prepare(
    'INSERT INTO manual_requests (user_id, manual_code, manual_title, notes, email) VALUES (?, ?, ?, ?, ?)'
  ).bind(user_id, manual_code, manual_title || null, notes || null, email || null).run();

  return json({ success: true, message: 'Request logged — thank you' });
}

async function handleForgotPassword(request, env) {
  const { email } = await request.json();
  if (!email) return json({ error: 'Email required' }, 400);

  const allowed = await checkRateLimit(env, `reset:${email.toLowerCase()}`);
  if (!allowed) return json({ error: 'Too many requests. Please wait 15 minutes.' }, 429);

  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (user) {
    const token = generateToken();
    const expires = Math.floor(Date.now() / 1000) + 3600;
    await env.DB.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?').bind(token, expires, user.id).run();
    await sendPasswordResetEmail(email, token, env.SITE_URL, env.RESEND_API_KEY);
  }

  return json({ success: true, message: 'If an account exists, a reset link has been sent' });
}

async function handleResetPassword(request, env) {
  const { token, password } = await request.json();
  if (!token || !password) return json({ error: 'Token and password required' }, 400);
  if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);

  const user = await env.DB.prepare('SELECT id, reset_token_expires FROM users WHERE reset_token = ?').bind(token).first();
  if (!user || user.reset_token_expires < Math.floor(Date.now() / 1000)) return json({ error: 'Invalid or expired reset token' }, 400);

  const password_hash = await hashPassword(password);
  await env.DB.prepare('UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?')
    .bind(password_hash, user.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();

  return json({ success: true, message: 'Password reset successfully' });
}

// ── Cookie helpers ──────────────────────────────────────────────────────────

function setSessionCookie(response, sessionId) {
  const headers = new Headers(response.headers);
  headers.set('Set-Cookie', `lcw_session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`);
  return new Response(response.body, { status: response.status, headers });
}

function clearSessionCookie(response) {
  const headers = new Headers(response.headers);
  headers.set('Set-Cookie', `lcw_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  return new Response(response.body, { status: response.status, headers });
}

function getSessionCookie(request) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(/lcw_session=([^;]+)/);
  return match ? match[1] : null;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

// ── Main handler ────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    // Periodic session cleanup
    if (Math.random() < 0.01) {
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Math.floor(Date.now() / 1000)).run().catch(() => {});
      env.DB.prepare('DELETE FROM rate_limits WHERE timestamp < ?').bind(Math.floor(Date.now() / 1000) - RATE_LIMIT_WINDOW).run().catch(() => {});
    }

    try {
      if (path === '/api/auth/signup'          && request.method === 'POST')   return handleSignup(request, env);
      if (path === '/api/auth/verify'          && request.method === 'GET')    return handleVerify(request, env);
      if (path === '/api/auth/resend-verify'   && request.method === 'POST')   return handleResendVerify(request, env);
      if (path === '/api/auth/login'           && request.method === 'POST')   return handleLogin(request, env);
      if (path === '/api/auth/logout'          && request.method === 'POST')   return handleLogout(request, env);
      if (path === '/api/auth/session'         && request.method === 'GET')    return handleSession(request, env);
      if (path === '/api/auth/get-settings'    && request.method === 'GET')    return handleGetSettings(request, env);
      if (path === '/api/auth/update-settings' && request.method === 'POST')   return handleUpdateSettings(request, env);
      if (path === '/api/auth/change-password' && request.method === 'POST')   return handleChangePassword(request, env);
      if (path === '/api/auth/change-email'    && request.method === 'POST')   return handleChangeEmail(request, env);
      if (path === '/api/auth/confirm-email'   && request.method === 'GET')    return handleConfirmEmail(request, env);
      if (path === '/api/auth/request-delete'  && request.method === 'POST')   return handleRequestDelete(request, env);
      if (path === '/api/auth/confirm-delete'  && request.method === 'GET')    return handleConfirmDelete(request, env);
      if (path === '/api/auth/download'        && request.method === 'POST')   return handleDownload(request, env);
      if (path === '/api/auth/request-manual'  && request.method === 'POST')   return handleRequestManual(request, env);
      if (path === '/api/auth/forgot-password' && request.method === 'POST')   return handleForgotPassword(request, env);
      if (path === '/api/auth/reset-password'  && request.method === 'POST')   return handleResetPassword(request, env);

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: 'Internal server error' }, 500);
    }
  }
};
