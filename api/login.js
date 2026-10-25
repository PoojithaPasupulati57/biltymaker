
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashPin(pin, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(`pin:${pin}`)
    .digest('hex');
}

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

  const email = String(req.body?.email || '').trim().toLowerCase();
  const pin = String(req.body?.pin || '');
  const secret = process.env.SESSION_SECRET;

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !/^\d{6}$/.test(pin)
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Enter a valid email and 6-digit PIN.'
    });
  }

  if (!secret || secret.length < 32 || !process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'Login is not configured.'
    });
  }

  try {
    const db = getPool();
    const user = await db.query(
      `SELECT email, pin_hash
       FROM public.app_users
       WHERE email = $1 AND email_verified = TRUE`,
      [email]
    );

    if (!user.rowCount) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid email or PIN.'
      });
    }

    const expected = Buffer.from(user.rows[0].pin_hash, 'hex');
    const supplied = Buffer.from(hashPin(pin, secret), 'hex');

    const matches =
      expected.length === supplied.length &&
      crypto.timingSafeEqual(expected, supplied);

    if (!matches) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid email or PIN.'
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(token, secret);

    await db.query(
      `INSERT INTO public.app_sessions
         (user_email, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [email, tokenHash]
    );

    res.setHeader(
      'Set-Cookie',
      `bm_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    );

    return res.status(200).json({
      ok: true,
      email
    });
  } catch (error) {
    console.error('Login failed:', error?.message || 'Unknown error');

    return res.status(500).json({
      ok: false,
      error: 'Could not log in. Please try again.'
    });
  }
}
