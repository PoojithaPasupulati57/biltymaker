
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

function hashPin(pin, secret) {
  return crypto.createHmac('sha256', secret).update(`pin:${pin}`).digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const email = String(req.body?.email || '').trim().toLowerCase();
  const pin = String(req.body?.pin || '');
  const resetToken = String(req.body?.resetToken || '');
  const otpSecret = process.env.OTP_SECRET;

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !/^\d{6}$/.test(pin) ||
    !/^[a-f0-9]{64}$/.test(resetToken)
  ) {
    return res.status(400).json({ ok: false, error: 'Invalid reset details.' });
  }

  if (!otpSecret || otpSecret.length < 32 || !process.env.DATABASE_URL) {
    return res.status(500).json({ ok: false, error: 'PIN reset is not configured.' });
  }

  let client;
  try {
    client = await getPool().connect();
    await client.query('BEGIN');

    const tokenHash = hashToken(resetToken, otpSecret);
    const result = await client.query(
      `SELECT id FROM public.registration_tokens
       WHERE email = $1 AND token_hash = $2
         AND consumed_at IS NULL AND expires_at > NOW()
       LIMIT 1 FOR UPDATE`,
      [email, tokenHash]
    );

    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(401).json({
        ok: false,
        error: 'Reset verification expired. Please verify your email again.'
      });
    }

    const user = await client.query(
      `UPDATE public.app_users
       SET pin_hash = $1
       WHERE email = $2 AND email_verified = TRUE
       RETURNING email`,
      [hashPin(pin, otpSecret), email]
    );

    if (!user.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ ok: false, error: 'Account not found.' });
    }

    await client.query(
      `UPDATE public.registration_tokens SET consumed_at = NOW() WHERE id = $1`,
      [result.rows[0].id]
    );

    await client.query(
      `UPDATE public.app_sessions SET revoked_at = NOW()
       WHERE user_email = $1 AND revoked_at IS NULL`,
      [email]
    );

    await client.query('COMMIT');
    return res.status(200).json({ ok: true, message: 'PIN reset successfully. Please log in again.' });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('PIN reset failed:', error?.message || 'Unknown error');
    return res.status(500).json({ ok: false, error: 'Could not reset PIN.' });
  } finally {
    client?.release();
  }
}
