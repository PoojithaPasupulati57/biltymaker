
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');
}

function getSessionToken(req) {
  const cookies = String(req.headers.cookie || '').split(';');

  for (const cookie of cookies) {
    const separator = cookie.indexOf('=');
    if (separator === -1) continue;

    if (cookie.slice(0, separator).trim() === 'bm_session') {
      const token = cookie.slice(separator + 1).trim();
      return /^[a-f0-9]{64}$/.test(token) ? token : '';
    }
  }

  return '';
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({
      ok: false,
      error: 'Method not allowed'
    });
  }

  res.setHeader(
    'Set-Cookie',
    'bm_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
  );

  const token = getSessionToken(req);
  const secret = process.env.SESSION_SECRET;

  if (!token) {
    return res.status(200).json({ ok: true });
  }

  if (!secret || secret.length < 32 || !process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'Logout is not configured.'
    });
  }

  try {
    const db = getPool();

    await db.query(
      `UPDATE public.app_sessions
       SET revoked_at = NOW()
       WHERE token_hash = $1
         AND revoked_at IS NULL`,
      [hashToken(token, secret)]
    );

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Logout failed:', error?.message || 'Unknown error');

    return res.status(500).json({
      ok: false,
      error: 'Could not complete logout.'
    });
  }
}
