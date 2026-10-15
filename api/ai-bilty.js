export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok:false });
  const image = req.body?.image || '';
  if (!image.startsWith('data:image')) return res.status(400).json({ ok:false, error:'No image' });
  const prompt = `You are a document parser for Indian transport bilty / goods receipt papers. Extract EVERY visible field. Reply with ONLY valid JSON, no markdown:
{"company":"","tag":"","motto":"","jurisdiction":"","address":"","phones":[],"gst":"","pan":"","no":"","date":"","lorry":"","from":"","to":"","consignor":"","consignee":"","rows":[["qty","description","weight"]],"rate":"","freight":0,"hamali":0,"statistical":0,"advance":0,"columns":[],"chargeRows":[],"footerNotes":[],"terms":""}
Rules: numbers as numbers; empty string if not visible; keep original spelling.`;
  const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key='+process.env.GEMINI_API_KEY, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ contents:[{ parts:[
      { text: prompt },
      { inline_data: { mime_type: image.split(';')[0].split(':')[1], data: image.split(',')[1] } }
    ]}]})
  });
  if (!r.ok) return res.status(500).json({ ok:false, error:'AI service error' });
  const j = await r.json();
  let text = (j?.candidates?.[0]?.content?.parts?.[0]?.text || '{}').replace(/```json|```/g,'').trim();
  try { res.json({ ok:true, data: JSON.parse(text) }); }
  catch { res.status(500).json({ ok:false, error:'AI reply not parseable' }); }
}
