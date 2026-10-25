
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
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
      error: 'Owner approval is not configured.'
    });
  }

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: 'Please log in with the owner account.'
    });
  }

  const paymentId = Number(req.body?.paymentId);
  const decision = String(req.body?.decision || '').toLowerCase();

  if (!Number.isSafeInteger(paymentId) || paymentId < 1 ||
      !['verified', 'rejected'].includes(decision)) {
    return res.status(400).json({
      ok: false,
      error: 'Provide a valid payment ID and decision.'
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
      `UPDATE public.payment_requests
       SET status = $1,
           verified_at = CASE
             WHEN $1 = 'verified' THEN NOW()
             ELSE NULL
           END,
           verified_by = $2
       WHERE id = $3
         AND status = 'pending'
       RETURNING id, user_email, status`,
      [decision, ownerEmail, paymentId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        ok: false,
        error: 'Pending payment not found. It may already have been reviewed.'
      });
    }

    return res.status(200).json({
      ok: true,
      payment: result.rows[0]
    });
  } catch (error) {
    console.error(
      'Payment approval failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not update payment status.'
    });
  }
}
