
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

  const secret = process.env.SESSION_SECRET;
  const ownerEmail = String(process.env.OWNER_EMAIL || '')
    .trim()
    .toLowerCase();

  const cookie = String(req.headers.cookie || '');
  const match = cookie.match(
    /(?:^|;\s*)bm_session=([a-f0-9]{64})(?:;|$)/
  );
  const token = match?.[1];

  if (!secret || secret.length < 32 || !process.env.DATABASE_URL || !ownerEmail) {
    return res.status(500).json({
      ok: false,
      error: 'Owner payment review is not configured.'
    });
  }

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: 'Please log in with the owner account.'
    });
  }

  try {
    const db = getPool();
    const tokenHash = hashToken(token, secret);

    const session = await db.query(
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

    if (
      !session.rowCount ||
      session.rows[0].user_email.toLowerCase() !== ownerEmail
    ) {
      return res.status(403).json({
        ok: false,
        error: 'Owner access required.'
      });
    }

    const result = await db.query(
      `SELECT id, user_email, amount_paise, plan_type, utr, status, created_at
       FROM public.payment_requests
       WHERE status = 'pending'
       ORDER BY created_at ASC
       LIMIT 100`
    );

    return res.status(200).json({
      ok: true,
      payments: result.rows
    });
  } catch (error) {
    console.error(
      'Pending payment lookup failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not retrieve pending payments.'
    });
  }
}
