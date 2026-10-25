
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashOtp(email, code, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${email}:${code}`)
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

  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const otp = String(req.body?.otp || '').trim();
  const secret = process.env.OTP_SECRET;

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.length > 254 ||
    !/^[A-Za-z][a-z][0-9][A-Za-z][a-z][0-9]$/.test(otp)
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Enter a valid email and reset code.'
    });
  }

  if (
    !secret || secret.length < 32 ||
    !process.env.DATABASE_URL
  ) {
    return res.status(500).json({
      ok: false,
      error: 'PIN reset verification is not configured.'
    });
  }

  let client;

  try {
    const db = getPool();
    client = await db.connect();
    await client.query('BEGIN');

    // Only a registered, verified account can reset its PIN.
    const user = await client.query(
      `SELECT id
       FROM public.app_users
       WHERE email = $1 AND email_verified = TRUE
       LIMIT 1`,
      [email]
    );

    if (!user.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        ok: false,
        error: 'Invalid or expired reset code.'
      });
    }

    const result = await client.query(
      `SELECT id, otp_hash, expires_at, attempts
       FROM public.email_otp_challenges
       WHERE email = $1 AND consumed_at IS NULL
       ORDER BY created_at DESC, id DESC
       LIMIT 1
       FOR UPDATE`,
      [email]
    );

    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        ok: false,
        error: 'Invalid or expired reset code. Request a new one.'
      });
    }

    const challenge = result.rows[0];

    if (
      Number(challenge.attempts) >= 5 ||
      new Date(challenge.expires_at).getTime() <= Date.now()
    ) {
      await client.query(
        `UPDATE public.email_otp_challenges
         SET consumed_at = NOW()
         WHERE id = $1`,
        [challenge.id]
      );
      await client.query('COMMIT');

      return res.status(400).json({
        ok: false,
        error: 'Invalid or expired reset code. Request a new one.'
      });
    }

    const expected = Buffer.from(challenge.otp_hash, 'hex');
    const supplied = Buffer.from(
      hashOtp(email, otp, secret),
      'hex'
    );

    const matches =
      expected.length === supplied.length &&
      crypto.timingSafeEqual(expected, supplied);

    if (!matches) {
      const attempts = Number(challenge.attempts) + 1;

      await client.query(
        `UPDATE public.email_otp_challenges
         SET attempts = $1,
             consumed_at = CASE
               WHEN $1 >= 5 THEN NOW()
               ELSE consumed_at
             END
         WHERE id = $2`,
        [attempts, challenge.id]
      );

      await client.query('COMMIT');

      return res.status(400).json({
        ok: false,
        error: attempts >= 5
          ? 'Too many attempts. Request a new code.'
          : 'Incorrect reset code.'
      });
    }

    // Consume the OTP so it cannot be reused.
    await client.query(
      `UPDATE public.email_otp_challenges
       SET consumed_at = NOW()
       WHERE id = $1`,
      [challenge.id]
    );

    // Invalidate old registration tokens for this email.
    await client.query(
      `UPDATE public.registration_tokens
       SET consumed_at = NOW()
       WHERE email = $1 AND consumed_at IS NULL`,
      [email]
    );

    // Issue a one-time token compatible with reset-pin.js.
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(resetToken, secret);

    await client.query(
      `INSERT INTO public.registration_tokens
         (email, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`,
      [email, tokenHash]
    );

    await client.query('COMMIT');

    return res.status(200).json({
      ok: true,
      resetToken,
      message: 'Email verified. You can now set a new PIN.'
    });
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
    }

    console.error(
      'PIN reset verification failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not verify the reset code. Please try again.'
    });
  } finally {
    client?.release();
  }
}
