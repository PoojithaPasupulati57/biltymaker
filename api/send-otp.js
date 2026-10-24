
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { getPool } from '../lib/db.js';

const WINDOW_MS = 5 * 60 * 1000;

const U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const L = 'abcdefghijklmnopqrstuvwxyz';
const D = '0123456789';

function randomChar(chars) {
  return chars[crypto.randomInt(0, chars.length)];
}

function generateOtp() {
  return (
    randomChar(U) +
    randomChar(L) +
    randomChar(D) +
    randomChar(U) +
    randomChar(L) +
    randomChar(D)
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

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Invalid email'
    });
  }

  const secret = process.env.OTP_SECRET;
  const gmailUser = process.env.GMAIL_USER;
  const gmailPassword = process.env.GMAIL_APP_PASSWORD;

  if (
    !secret ||
    secret.length < 32 ||
    !gmailUser ||
    !gmailPassword ||
    !process.env.DATABASE_URL
  ) {
    console.error('OTP service configuration is incomplete');
    return res.status(500).json({
      ok: false,
      error: 'Email service is not configured'
    });
  }

  let challengeId;

  try {
    const db = getPool();

    // Limit OTP requests to 3 per email in 15 minutes.
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

    // Only the newest challenge can be used.
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
        name: 'BiltyMaker',
        address: gmailUser
      },
      to: email,
      subject: 'Your BiltyMaker verification code',
      text:
        `Your BiltyMaker verification code is: ${code}\n\n` +
        'This code expires in 5 minutes. ' +
        'If you did not request it, ignore this email.',
      html:
        '<div style="font-family:Arial;padding:24px;background:#f6f4ec">' +
        '<h2 style="color:#145c33">BiltyMaker verification</h2>' +
        '<p>Your email verification code is:</p>' +
        `<p style="font-size:32px;font-weight:bold;letter-spacing:5px;color:#c22a63">${code}</p>` +
        '<p>This code expires in 5 minutes. If you did not request it, ignore this email.</p>' +
        '</div>'
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('OTP request failed:', error?.message || 'Unknown error');

    if (challengeId && process.env.DATABASE_URL) {
      try {
        await getPool().query(
          `UPDATE public.email_otp_challenges
           SET consumed_at = NOW()
           WHERE id = $1`,
          [challengeId]
        );
      } catch {
        console.error('Could not invalidate failed OTP challenge');
      }
    }

    return res.status(500).json({
      ok: false,
      error: 'Could not send OTP. Please try again later.'
    });
  }
}
