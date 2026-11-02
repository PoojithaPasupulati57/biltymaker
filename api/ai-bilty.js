
import crypto from 'crypto';
import { getPool } from '../lib/db.js';

function hashToken(token, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({
      ok: false,
      error: 'Method not allowed'
    });
  }

  // Require a valid login session.
  const cookie = String(req.headers.cookie || '');
  const match = cookie.match(
    /(?:^|;\s*)bm_session=([a-f0-9]{64})(?:;|$)/
  );
  const token = match?.[1];
  const secret = process.env.SESSION_SECRET;

  if (!token || !secret || secret.length < 32) {
    return res.status(401).json({
      ok: false,
      error: 'Please log in.'
    });
  }

  if (!process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: 'Database is not configured.'
    });
  }

  try {
    const db = getPool();
    const tokenHash = hashToken(token, secret);

    const session = await db.query(
      `SELECT s.user_email
       FROM public.app_sessions s
       JOIN public.app_users u ON u.email = s.user_email
       WHERE s.token_hash = $1
         AND s.revoked_at IS NULL
         AND s.expires_at > NOW()
         AND u.email_verified = TRUE
       LIMIT 1`,
      [tokenHash]
    );

    if (!session.rowCount) {
      return res.status(401).json({
        ok: false,
        error: 'Your session has expired. Please log in again.'
      });
    }

    const email = session.rows[0].user_email.toLowerCase();
    const ownerEmail = String(process.env.OWNER_EMAIL || '')
      .trim()
      .toLowerCase();

    const isOwner = Boolean(ownerEmail) && email === ownerEmail;

    if (!isOwner) {
      const payment = await db.query(
        `SELECT id
         FROM public.payment_requests
         WHERE user_email = $1
           AND status = 'verified'
         LIMIT 1`,
        [email]
      );

      if (!payment.rowCount) {
        return res.status(403).json({
          ok: false,
          error: 'Payment approval is required to use bilty generation.'
        });
      }
    }
  } catch (error) {
    console.error(
      'Access check failed:',
      error?.message || 'Unknown error'
    );

    return res.status(500).json({
      ok: false,
      error: 'Could not verify access.'
    });
  }

  // Check image input.
  const image = req.body?.image || '';

  const imageMatch = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(image);

  if (!imageMatch) {
    return res.status(400).json({
      ok: false,
      error: 'Please provide a valid JPEG, PNG or WebP image.'
    });
  }

  if (image.length > 7 * 1024 * 1024) {
    return res.status(413).json({
      ok: false,
      error: 'Image is too large. Please use an image under 7 MB.'
    });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      ok: false,
      error: 'AI service is not configured.'
    });
  }

  const prompt = `You are a document parser for Indian transport bilty / goods receipt papers. Extract EVERY visible field. Reply with ONLY valid JSON, no markdown:
{"company":"","tag":"","motto":"","jurisdiction":"","address":"","phones":[],"gst":"","pan":"","no":"","date":"","lorry":"","from":"","to":"","consignor":"","consignee":"","rows":[["qty","description","weight"]],"rate":"","freight":0,"hamali":0,"statistical":0,"advance":0,"columns":[],"chargeRows":[],"footerNotes":[],"terms":""}
Rules: numbers as numbers; empty string if not visible; keep original spelling.`;

  try {
    const response = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey
        },
        body: JSON.stringify({
          contents: [{
            parts: [
              { text: prompt },
              {
                inline_data: {
                  mime_type: imageMatch[1],
                  data: imageMatch[2]
                }
              }
            ]
          }]
        })
      }
    );

    if (!response.ok) {
      console.error('Gemini API returned status:', response.status);
      return res.status(502).json({
        ok: false,
        error: 'AI service error. Please try again.'
      });
    }

    const result = await response.json();

    const text = (
      result?.candidates?.[0]?.content?.parts?.[0]?.text || '{}'
    ).replace(/```json|```/g, '').trim();

    try {
      return res.status(200).json({
        ok: true,
        data: JSON.parse(text)
      });
    } catch {
      return res.status(502).json({
        ok: false,
        error: 'AI reply was not valid JSON. Please try again.'
      });
    }
  } catch (error) {
    console.error(
      'AI bilty request failed:',
      error?.message || 'Unknown error'
    );

    return res.status(502).json({
      ok: false,
      error: 'Could not contact the AI service.'
    });
  }
}
