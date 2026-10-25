
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
  const cookie = String(req.headers.cookie || '');
  const match = cookie.match(
    /(?:^|;\s*)bm_session=([a-f0-9]{64})(?:;|$)/
  );
  const token = match?.[1];

  if (!token || !secret || secret.length < 32) {
    return res.status(401).json({
      ok: false,
      error: 'Please log in.'
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

    if (!session.rowCount) {
      return res.status(401).json({
        ok: false,
        error: 'Session expired. Please log in again.'
      });
    }

    const email = session.rows[0].user_email;

    const payment = await db.query(
      `SELECT id, amount_paise, plan_type, utr, status, created_at, verified_at
       FROM public.payment_requests
       WHERE user_email = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [email]
    );

    if (!payment.rowCount) {
      return res.status(200).json({
        ok: true,
        status: 'not_submitted',
        payment: null
      });
    }

    return res.status(200).json({
      ok: true,
      status: payment.rows[0].status,
      payment: payment.rows[0]
    });
  } catch (error) {
    console.error(
      'Payment status check failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not retrieve payment status.'
    });
  }
}
