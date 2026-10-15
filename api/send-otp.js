import crypto from 'crypto';

const SECRET = process.env.OTP_SECRET || 'biltymaker-secret-change-me';
const WINDOW_MS = 5 * 60 * 1000;
const win = () => Math.floor(Date.now() / WINDOW_MS);

function otpFor(email, w) {
  const h = crypto.createHmac('sha256', SECRET).update(email + ':' + w).digest();
  return String(h.readUInt32BE(0) % 1000000).padStart(6, '0');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ ok:false, error:'Invalid email' });

  const code = otpFor(em, win());

  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sender: { name: 'BiltyMaker', email: 'poojithapasupuleti57@gmail.com' },
      to: [{ email: em }],
      subject: 'Your BiltyMaker OTP: ' + code,
      html: '<div style="font-family:Arial;padding:24px;background:#f6f4ec">' +
            '<h2 style="color:#145c33">Transport Bilty – Login OTP</h2>' +
            '<p style="font-size:34px;font-weight:800;letter-spacing:6px;color:#c22a63">' + code + '</p>' +
            '<p style="color:#666">Expires in 5 minutes. Ignore if not requested.</p></div>'
    })
  });

  if (!r.ok) {
    const t = await r.text();
    return res.status(500).json({ ok:false, error:'Send failed: ' + t.slice(0, 140) });
  }
  res.json({ ok:true });
}
