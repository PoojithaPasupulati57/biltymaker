import crypto from 'crypto';

const SECRET = process.env.OTP_SECRET || 'verifykey';
const WINDOW_MS = 5 * 60 * 1000;
const win = () => Math.floor(Date.now() / WINDOW_MS);
const U='ABCDEFGHIJKLMNOPQRSTUVWXYZ', L='abcdefghijklmnopqrstuvwxyz', D='0123456789';

function genotp(email, w) {
  const h = crypto.createHmac('sha256', SECRET).update(email + ':' + w).digest();
  return U[h[0]%26] + L[h[1]%26] + D[h[2]%10] + U[h[3]%26] + L[h[4]%26] + D[h[5]%10];
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  const code = String(req.body?.otp || '').trim().toUpperCase(); // case-insensitive = friendly
  const w = win();
  if (code === genotp(em, w).toUpperCase() || code === genotp(em, w - 1).toUpperCase()) return res.json({ ok:true });
  res.status(400).json({ ok:false, error:'Wrong or expired OTP — resend' });
}
