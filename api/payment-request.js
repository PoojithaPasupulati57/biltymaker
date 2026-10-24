
import { getPool } from '../lib/db.js';

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

  const utr = String(req.body?.utr || '').trim();
  const amount = Number(req.body?.amount);
  const plan = String(req.body?.plan || '');

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.length > 254 ||
    !/^[A-Za-z0-9-]{8,100}$/.test(utr) ||
    amount !== 5000 ||
    plan !== 'lifetime'
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Invalid payment request details'
    });
  }

  try {
    const db = getPool();

    // The account must already exist in the database.
    const user = await db.query(
      `SELECT email
       FROM public.app_users
       WHERE email = $1`,
      [email]
    );

    if (!user.rowCount) {
      return res.status(400).json({
        ok: false,
        error: 'Account registration is not completed yet'
      });
    }

    const result = await db.query(
      `INSERT INTO public.payment_requests
         (user_email, amount_paise, plan_type, utr, status)
       VALUES ($1, 500000, 'lifetime', $2, 'pending')
       ON CONFLICT (utr) DO NOTHING
       RETURNING id, status`,
      [email, utr]
    );

    if (!result.rowCount) {
      return res.status(409).json({
        ok: false,
        error: 'This UTR has already been submitted'
      });
    }

    return res.status(201).json({
      ok: true,
      status: 'pending'
    });
  } catch (error) {
    console.error(
      'Payment request failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not save payment request'
    });
  }
}
