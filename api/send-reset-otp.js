
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { getPool } from '../lib/db.js';

function generateOtp() {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';

  function pick(chars) {
    return chars[crypto.randomInt(0, chars.length)];
  }

  return (
    pick(upper) + pick(lower) + pick(digits) +
    pick(upper) + pick(lower) + pick(digits)
  );
}

function hashOtp(email, code, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${email}:${code}`)
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

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254) {
    return res.status(400).json({
      ok: false,
      error: 'Enter a valid email address.'
    });
  }

  const secret = process.env.OTP_SECRET;
  const gmailUser = process.env.GMAIL_USER;
  const gmailPassword = process.env.GMAIL_APP_PASSWORD;

  if (
    !secret || secret.length < 32 ||
    !gmailUser || !gmailPassword ||
    !process.env.DATABASE_URL
  ) {
    return res.status(500).json({
      ok: false,
      error: 'Email service is not configured.'
    });
  }

  let challengeId;

  try {
    const db = getPool();

    const user = await db.query(
      `SELECT id FROM public.app_users
       WHERE email = $1 AND email_verified = TRUE
       LIMIT 1`,
      [email]
    );

    if (!user.rowCount) {
      return res.status(404).json({
        ok: false,
        error: 'No verified account was found for this email.'
      });
    }

    const rate = await db.query(
      `SELECT COUNT(*)::int AS total
       FROM public.email_otp_challenges
       WHERE email = $1
         AND created_at > NOW() - INTERVAL '15 minutes'`,
      [email]
    );

    if (rate.rows[0].total >= 3) {
      return res.status(429).json({
        ok: false,
        error: 'Too many OTP requests. Try again in 15 minutes.'
      });
    }

    const code = generateOtp();
    const otpHash = hashOtp(email, code, secret);

    await db.query(
      `UPDATE public.email_otp_challenges
       SET consumed_at = NOW()
       WHERE email = $1 AND consumed_at IS NULL`,
      [email]
    );

    const inserted = await db.query(
      `INSERT INTO public.email_otp_challenges
         (email, otp_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '5 minutes')
       RETURNING id`,
      [email, otpHash]
    );

    challengeId = inserted.rows[0].id;

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: gmailUser,
        pass: gmailPassword.replace(/\s/g, '')
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000
    });

    await transporter.sendMail({
      from: {
        name: 'BiltyMaker PIN Reset',
        address: gmailUser
      },
      to: email,
      subject: 'Your BiltyMaker PIN reset code',
      text:
        `Your PIN reset verification code is: ${code}\n\n` +
        'This code expires in 5 minutes. If you did not request it, ignore this email.',
      html:
        '<div style="font-family:Arial;padding:24px;background:#f6f4ec">' +
        '<h2 style="color:#145c33">BiltyMaker PIN reset</h2>' +
        '<p>Your verification code is:</p>' +
        `<p style="font-size:32px;font-weight:bold;letter-spacing:5px">${code}</p>` +
        '<p>This code expires in 5 minutes.</p></div>'
    });

    return res.status(200).json({
      ok: true,
      message: 'If the account is eligible, a reset code has been sent.'
    });
  } catch (error) {
    console.error(
      'PIN reset OTP request failed:',
      error?.message || 'Unknown error'
    );

    if (challengeId) {
      await getPool().query(
        `UPDATE public.email_otp_challenges
         SET consumed_at = NOW()
         WHERE id = $1`,
        [challengeId]
      ).catch(() => {});
    }

    return res.status(500).json({
      ok: false,
      error: 'Could not send the reset code. Please try again.'
    });
  }
}
