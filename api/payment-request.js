
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');
}

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || '').split(';');

  for (const cookie of cookies) {
    const separator = cookie.indexOf('=');
    if (separator === -1) continue;

    const key = cookie.slice(0, separator).trim();
    const value = cookie.slice(separator + 1).trim();

    if (key === name) return value;
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

  const utr = String(req.body?.utr || '').trim();
  const amount = Number(req.body?.amount);
  const plan = String(req.body?.plan || '');

  if (
    !/^[A-Za-z0-9-]{8,100}$/.test(utr) ||
    amount !== 5000 ||
    plan !== 'lifetime'
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Invalid payment request details'
    });
  }

  const sessionToken = getCookie(req, 'bm_session');
  const secret = process.env.SESSION_SECRET;

  if (!sessionToken || !/^[a-f0-9]{64}$/.test(sessionToken)) {
    return res.status(401).json({
      ok: false,
      error: 'Please log in before submitting your payment.'
    });
  }

  if (!secret || secret.length < 32 || !process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'Payment verification is not configured.'
    });
  }

  try {
    const db = getPool();
    const tokenHash = hashToken(sessionToken, secret);

    // Identify the customer using their verified server-side session.
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
        error: 'Your session has expired. Please log in again.'
      });
    }

    // Never trust an email supplied by the browser.
    const email = session.rows[0].user_email;

    const result = await db.query(
      `INSERT INTO public.payment_requests
         (user_email, amount_paise, plan_type, utr, status)
       VALUES ($1, 500000, 'lifetime', $2, 'pending')
       ON CONFLICT (utr) DO NOTHING
       RETURNING id, status`,
      [email, utr]
    );

    if (!result.rowCount) {
      return res.status(409).json({
        ok: false,
        error: 'This UTR has already been submitted.'
      });
    }

    return res.status(201).json({
      ok: true,
      status: 'pending',
      message: 'Payment submitted for manual verification.'
    });
  } catch (error) {
    console.error(
      'Payment request failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not save payment request.'
    });
  }
}
