import crypto from 'crypto';

const SECRET = process.env.OTP_SECRET || 'verifykey'; // your salt, kept
const WINDOW_MS = 5 * 60 * 1000;
const win = () => Math.floor(Date.now() / WINDOW_MS);
const U='ABCDEFGHIJKLMNOPQRSTUVWXYZ', L='abcdefghijklmnopqrstuvwxyz', D='0123456789';

function genotp(email, w) {           // same pattern as your Python genotp(): Aa1Bb2
  const h = crypto.createHmac('sha256', SECRET).update(email + ':' + w).digest();
  return U[h[0]%26] + L[h[1]%26] + D[h[2]%10] + U[h[3]%26] + L[h[4]%26] + D[h[5]%10];
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ ok:false, error:'Invalid email' });

  const code = genotp(em, win());

  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sender: { name: 'BiltyMaker', email: 'poojithapasupuleti57@gmail.com' },
      to: [{ email: em }],
      subject: 'Your BiltyMaker OTP: ' + code,
      html: '<div style="font-family:Arial;padding:24px;background:#f6f4ec">' +
            '<h2 style="color:#145c33">Transport Bilty – Login OTP</h2>' +
            '<p style="font-size:34px;font-weight:800;letter-spacing:6px;color:#c22a63;font-family:monospace">' + code + '</p>' +
            '<p style="color:#666">Expires in 5 minutes. Upper/lower case does not matter. Ignore if not requested.</p></div>'
    })
  });

  if (!r.ok) {
    const t = await r.text();
    return res.status(500).json({ ok:false, error:'Send failed: ' + t.slice(0, 140) });
  }
  res.json({ ok:true });
}
