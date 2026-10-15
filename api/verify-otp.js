import crypto from 'crypto';

const SECRET = process.env.OTP_SECRET || 'biltymaker-secret-change-me';
const WINDOW_MS = 5 * 60 * 1000;
const win = () => Math.floor(Date.now() / WINDOW_MS);

function otpFor(email, w) {
  const hmac = crypto.createHmac('sha256', SECRET).update(email + ':' + w).digest();
  return String(hmac.readUInt32BE(0) % 1000000).padStart(6, '0');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  const code = String(req.body?.otp || '').trim();
  const w = win();
  if (code === otpFor(em, w) || code === otpFor(em, w - 1)) return res.json({ ok:true });
  res.status(400).json({ ok:false, error:'Wrong or expired OTP — resend' });
}
