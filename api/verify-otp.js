
import crypto from 'crypto';

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
    return res.status(405).json({
      ok: false,
      error: 'Method not allowed'
    });
  }

  const secret = process.env.OTP_SECRET;

  if (!secret || secret.length < 32) {
    return res.status(500).json({
      ok: false,
      error: 'OTP verification is not configured'
    });
  }

  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();

  const code = String(req.body?.otp || '')
    .trim();

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

  const w = win();
  const valid =
    code === genotp(email, w, secret) ||
    code === genotp(email, w - 1, secret);

  if (!valid) {
    return res.status(400).json({
      ok: false,
      error: 'Wrong or expired OTP — resend'
    });
  }

  return res.status(200).json({ ok: true });
}
