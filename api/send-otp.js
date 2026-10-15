import crypto from 'crypto';
import nodemailer from 'nodemailer';

const SECRET = process.env.OTP_SECRET || 'biltymaker-secret-change-me';
const WINDOW_MS = 5 * 60 * 1000;                 // OTP valid 5 minutes
const win = () => Math.floor(Date.now() / WINDOW_MS);

function otpFor(email, w) {                      // your genotp(), server-side & stateless
  const hmac = crypto.createHmac('sha256', SECRET).update(email + ':' + w).digest();
  return String(hmac.readUInt32BE(0) % 1000000).padStart(6, '0');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ ok:false, error:'Invalid email' });

  const code = otpFor(em, win());

  const transporter = nodemailer.createTransport({   // ← your smtplib reference, in Node
    host: 'smtp.gmail.com', port: 465, secure: true,
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
  });

  try {
    await transporter.sendMail({
      from: '"BiltyMaker – Mother India Transport" <' + process.env.GMAIL_USER + '>',
      to: em,
      subject: 'Your BiltyMaker OTP: ' + code,
      html: '<div style="font-family:Arial;padding:24px;background:#f6f4ec">' +
            '<h2 style="color:#145c33">Mother India Transport – BiltyMaker</h2>' +
            '<p style="font-size:34px;font-weight:800;letter-spacing:6px;color:#c22a63">' + code + '</p>' +
            '<p style="color:#666">Expires in 5 minutes. Ignore if not requested.</p></div>'
    });
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error:'Email send failed (' + (e.responseCode || e.code || e.message) + ')' });
  }
}
