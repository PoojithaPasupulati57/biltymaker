
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
  const token = String(req.body?.registrationToken || '');
  const secret = process.env.OTP_SECRET;

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !/^[6-9]\d{9}$/.test(phone) ||
    !/^\d{6}$/.test(pin) ||
    !/^[a-f0-9]{64}$/.test(token)
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Enter a valid email, 10-digit phone number, 6-digit PIN and verification token.'
    });
  }

  if (!secret || secret.length < 32 || !process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'Registration is not configured'
    });
  }

  try {
    const db = getPool();
    const client = await db.connect();

    try {
      await client.query('BEGIN');

      const tokenHash = hashToken(token, secret);

      const verified = await client.query(
        `SELECT id
         FROM public.registration_tokens
         WHERE email = $1
           AND token_hash = $2
           AND consumed_at IS NULL
           AND expires_at > NOW()
         LIMIT 1
         FOR UPDATE`,
        [email, tokenHash]
      );

      if (!verified.rowCount) {
        await client.query('ROLLBACK');
        return res.status(401).json({
          ok: false,
          error: 'Verification expired. Please verify your email again.'
        });
      }

      const pinHash = hashPin(pin, secret);

      await client.query(
        `INSERT INTO public.app_users
           (email, phone, pin_hash, email_verified)
         VALUES ($1, $2, $3, TRUE)`,
        [email, phone, pinHash]
      );

      await client.query(
        `UPDATE public.registration_tokens
         SET consumed_at = NOW()
         WHERE email = $1 AND token_hash = $2`,
        [email, tokenHash]
      );

      await client.query('COMMIT');

      return res.status(201).json({
        ok: true,
        message: 'Account created. Please implement secure login before granting access.'
      });
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});

      if (error.code === '23505') {
        return res.status(409).json({
          ok: false,
          error: 'This email or phone number is already registered.'
        });
      }

      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(
      'Registration failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not create account.'
    });
  }
}

