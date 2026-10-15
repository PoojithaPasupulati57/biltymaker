const store = globalThis.otpStore || (globalThis.otpStore = new Map());
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ ok:false, error:'Invalid email' });
  const now = Date.now();
  const rec = store.get(em) || { tries:[], code:null, expiry:0 };
  rec.tries = rec.tries.filter(t => now - t < 10*60*1000);
  if (rec.tries.length >= 3) return res.status(429).json({ ok:false, error:'Too many tries. Wait 10 minutes.' });
  const code = String(Math.floor(100000 + Math.random()*900000));
  rec.tries.push(now); rec.code = code; rec.expiry = now + 5*60*1000;
  store.set(em, rec);
  const r = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method:'POST',
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify({
      service_id: process.env.EMAILJS_SERVICE_ID,
      template_id: process.env.EMAILJS_TEMPLATE_ID,
      user_id: process.env.EMAILJS_PUBLIC_KEY,
      template_params: { otp: code, to_email: em }
    })
  });
  if (!r.ok) return res.status(500).json({ ok:false, error:'Email send failed' });
  res.json({ ok:true });
}
