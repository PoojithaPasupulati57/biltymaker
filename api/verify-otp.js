
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

  const email = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.otp || '').trim();
  const secret = process.env.OTP_SECRET;

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !/^[A-Za-z][a-z][0-9][A-Za-z][a-z][0-9]$/.test(code)
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Invalid email or OTP format'
    });
  }

  if (!secret || secret.length < 32 || !process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'OTP verification is not configured'
    });
  }

  try {
    const db = getPool();
    const client = await db.connect();

    let registrationToken;

    try {
      await client.query('BEGIN');

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
          error: 'Wrong or expired OTP. Request a new one.'
        });
      }

      const challenge = result.rows[0];

      if (
        challenge.attempts >= 5 ||
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
          error: 'Wrong or expired OTP. Request a new one.'
        });
      }

      const expected = Buffer.from(challenge.otp_hash, 'hex');
      const supplied = Buffer.from(
        hashOtp(email, code, secret),
        'hex'
      );

      const matches =
        expected.length === supplied.length &&
        crypto.timingSafeEqual(expected, supplied);

      if (!matches) {
        const attempts = challenge.attempts + 1;

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
            ? 'Too many attempts. Request a new OTP.'
            : 'Wrong OTP.'
        });
      }

      await client.query(
        `UPDATE public.email_otp_challenges
         SET consumed_at = NOW()
         WHERE id = $1`,
        [challenge.id]
      );

      registrationToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = hashToken(registrationToken, secret);

      await client.query(
        `UPDATE public.registration_tokens
         SET consumed_at = NOW()
         WHERE email = $1 AND consumed_at IS NULL`,
        [email]
      );

      await client.query(
        `INSERT INTO public.registration_tokens
           (email, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`,
        [email, tokenHash]
      );

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }

    return res.status(200).json({
      ok: true,
      registrationToken
    });
  } catch (error) {
    console.error(
      'OTP verification failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not verify OTP. Please try again.'
    });
  }
}
