const store = globalThis.otpStore || (globalThis.otpStore = new Map());
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const em = String(req.body?.email || '').toLowerCase();
  const rec = store.get(em);
  if (!rec || Date.now() > rec.expiry) return res.status(400).json({ ok:false, error:'OTP expired — resend' });
  if (rec.code !== String(req.body?.otp || '').trim()) return res.status(400).json({ ok:false, error:'Wrong OTP' });
  store.delete(em);
  res.json({ ok:true });
}
