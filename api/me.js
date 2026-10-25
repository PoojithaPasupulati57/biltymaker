
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({
      ok: false,
      error: 'Method not allowed'
    });
  }

  const cookie = String(req.headers.cookie || '');
  const match = cookie.match(/(?:^|;\s*)bm_session=([a-f0-9]{64})(?:;|$)/);
  const token = match?.[1];
  const secret = process.env.SESSION_SECRET;

  if (!token || !secret || secret.length < 32) {
    return res.status(401).json({
      ok: false,
      error: 'Please log in.'
    });
  }

  try {
    const db = getPool();
    const tokenHash = hashToken(token, secret);

    const result = await db.query(
      `SELECT s.user_email
       FROM public.app_sessions s
       JOIN public.app_users u ON u.email = s.user_email
       WHERE s.token_hash = $1
         AND s.revoked_at IS NULL
         AND s.expires_at > NOW()
         AND u.email_verified = TRUE
       LIMIT 1`,
      [tokenHash]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        ok: false,
        error: 'Session expired. Please log in again.'
      });
    }

    return res.status(200).json({
      ok: true,
      email: result.rows[0].user_email
    });
  } catch (error) {
    console.error('Session check failed:', error?.message || 'Unknown error');

    return res.status(500).json({
      ok: false,
      error: 'Could not verify session.'
    });
  }
}
