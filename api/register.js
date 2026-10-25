
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');
}

function hashPin(pin, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(`pin:${pin}`)
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
  const phone = String(req.body?.phone || '').trim();
  const pin = String(req.body?.pin || '');
  const registrationToken = String(req.body?.registrationToken || '');

  const otpSecret = process.env.OTP_SECRET;
  const sessionSecret = process.env.SESSION_SECRET;

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !/^[6-9]\d{9}$/.test(phone) ||
    !/^\d{6}$/.test(pin) ||
    !/^[a-f0-9]{64}$/.test(registrationToken)
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Enter a valid email, phone number, PIN and verification token.'
    });
  }

  if (
    !otpSecret || otpSecret.length < 32 ||
    !sessionSecret || sessionSecret.length < 32 ||
    !process.env.DATABASE_URL
  ) {
    return res.status(500).json({
      ok: false,
      error: 'Registration is not configured.'
    });
  }

  let client;

  try {
    const db = getPool();
    client = await db.connect();

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const registrationHash = hashToken(registrationToken, otpSecret);
    const sessionHash = hashToken(sessionToken, sessionSecret);
    const pinHash = hashPin(pin, otpSecret);

    await client.query('BEGIN');

    const verified = await client.query(
      `SELECT id
       FROM public.registration_tokens
       WHERE email = $1
         AND token_hash = $2
         AND consumed_at IS NULL
         AND expires_at > NOW()
       LIMIT 1
       FOR UPDATE`,
      [email, registrationHash]
    );

    if (!verified.rowCount) {
      await client.query('ROLLBACK');
      return res.status(401).json({
        ok: false,
        error: 'Verification expired. Please verify your email again.'
      });
    }

    await client.query(
      `INSERT INTO public.app_users
         (email, phone, pin_hash, email_verified)
       VALUES ($1, $2, $3, TRUE)`,
      [email, phone, pinHash]
    );

    await client.query(
      `UPDATE public.registration_tokens
       SET consumed_at = NOW()
       WHERE id = $1`,
      [verified.rows[0].id]
    );

    await client.query(
      `INSERT INTO public.app_sessions
         (user_email, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [email, sessionHash]
    );

    await client.query('COMMIT');

    res.setHeader(
      'Set-Cookie',
      `bm_session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    );

    return res.status(201).json({
      ok: true,
      email,
      message: 'Account created. Please submit your payment for verification.'
    });
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
    }

    if (error.code === '23505') {
      return res.status(409).json({
        ok: false,
        error: 'This email or phone number is already registered.'
      });
    }

    console.error(
      'Registration failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not create account.'
    });
  } finally {
    client?.release();
  }
}
