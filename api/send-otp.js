
import crypto from 'crypto';
import nodemailer from 'nodemailer';

const WINDOW_MS = 5 * 60 * 1000;
const win = () => Math.floor(Date.now() / WINDOW_MS);

const U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const L = 'abcdefghijklmnopqrstuvwxyz';
const D = '0123456789';

function genotp(email, w, secret) {
  const h = crypto
    .createHmac('sha256', secret)
    .update(email + ':' + w)
    .digest();

  return (
    U[h[0] % 26] +
    L[h[1] % 26] +
    D[h[2] % 10] +
    U[h[3] % 26] +
    L[h[4] % 26] +
    D[h[5] % 10]
  );
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const email = String(req.body?.email || '').trim().toLowerCase();

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

  if (!secret || secret.length < 32 || !gmailUser || !gmailPassword) {
    console.error('Missing or invalid OTP/email environment configuration');
    return res.status(500).json({
      ok: false,
      error: 'Email service is not configured'
    });
  }

  const code = genotp(email, win(), secret);

  try {
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
        'This code expires within 5 minutes. ' +
        'If you did not request it, ignore this email.',
      html:
        '<div style="font-family:Arial;padding:24px;background:#f6f4ec">' +
        '<h2 style="color:#145c33">BiltyMaker verification</h2>' +
        '<p>Your email verification code is:</p>' +
        `<p style="font-size:32px;font-weight:bold;letter-spacing:5px;color:#c22a63">${code}</p>` +
        '<p>This code expires within 5 minutes. If you did not request it, ignore this email.</p>' +
        '</div>'
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('OTP email delivery failed:', error?.message || 'Unknown error');

    return res.status(500).json({
      ok: false,
      error: 'Could not send OTP. Please try again later.'
    });
  }
}
