
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

  if (!process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'Database is not configured.'
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

    const email = result.rows[0].user_email;
    const ownerEmail = String(process.env.OWNER_EMAIL || '')
      .trim()
      .toLowerCase();

    const isOwner = Boolean(ownerEmail) && email.toLowerCase() === ownerEmail;

    const payment = await db.query(
      `SELECT status
       FROM public.payment_requests
       WHERE user_email = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [email]
    );

    const paymentApproved = payment.rows.some(
      row => row.status === 'verified'
    );

    const hasAccess = isOwner || paymentApproved;

    return res.status(200).json({
      ok: true,
      email,
      isOwner,
      paymentStatus: paymentApproved
        ? 'verified'
        : payment.rowCount
          ? payment.rows[0].status
          : 'not_submitted',
      hasAccess
    });
  } catch (error) {
    console.error(
      'Session check failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not verify session.'
    });
  }
}
