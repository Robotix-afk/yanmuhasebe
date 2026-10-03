'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const {
  PORT = 3000,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SMTP_HOST,
  SMTP_PORT = '587',
  SMTP_USER,
  SMTP_PASS,
  MAIL_FROM,
  OTP_PEPPER,
  ALLOWED_ORIGINS = '',
  RECAPTCHA_SECRET,
  CAPTCHA_HOSTS = 'robotix-afk.github.io,localhost',
  CLOUD_PASS_SUFFIX = 'Ym#a7' // index.html içindeki cloudPassword() ile AYNI olmalı
} = process.env;

for (const [k, v] of Object.entries({ SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM, OTP_PEPPER })) {
  if (!v) { console.error('Eksik ortam değişkeni: ' + k); process.exit(1); }
}

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const mailer = nodemailer.createTransport({
  host: SMTP_HOST, port: Number(SMTP_PORT), secure: Number(SMTP_PORT) === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

const OTP_TTL_MS = 5 * 60 * 1000;       // 5 dakika
const RESET_TTL_MS = 10 * 60 * 1000;    // doğrulama sonrası şifre belirleme süresi
const MAX_ATTEMPTS = 5;
const COOLDOWN_MS = 60 * 1000;

const h = (s) => crypto.createHmac('sha256', OTP_PEPPER).update(String(s)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const normEmail = (e) => { e = String(e || '').trim().toLowerCase(); return /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(e) && e.length <= 254 ? e : null; };
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Sunucu hatası. Lütfen tekrar deneyin.' }); });
const likeEscape = (s) => s.replace(/[\\%_]/g, '\\$&');

async function verifyCaptcha(token, ip) {
  if (!RECAPTCHA_SECRET) { console.warn('RECAPTCHA_SECRET tanımlı değil, captcha doğrulaması atlandı.'); return true; }
  if (!token) return false;
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ secret: RECAPTCHA_SECRET, response: token, remoteip: ip || '' })
  });
  const j = await r.json().catch(() => ({}));
  return j.success === true && CAPTCHA_HOSTS.split(',').map((x) => x.trim()).includes(String(j.hostname || ''));
}

async function findProfile(email) {
  const { data } = await sb.from('profiles').select('id,full_name').ilike('email', likeEscape(email)).limit(1).maybeSingle();
  return data || null;
}

async function latestReset(email, extra) {
  let q = sb.from('password_resets').select('*').eq('email', email).eq('used', false);
  if (extra) q = extra(q);
  const { data } = await q.order('created_at', { ascending: false }).limit(1).maybeSingle();
  return data || null;
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
const origins = ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => (!origin || origins.includes(origin)) ? cb(null, true) : cb(new Error('CORS')),
  methods: ['GET', 'POST'], maxAge: 600
}));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));
const strict = rateLimit({ windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false, message: { error: 'Çok fazla deneme. Lütfen biraz sonra tekrar deneyin.' } });

app.get('/health', (_req, res) => res.json({ ok: true }));

// 1) OTP üret ve e-posta ile gönder
app.post('/forgot-password', strict, wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  if (!email) return res.status(400).json({ error: 'Geçerli bir e-posta girin.' });
  if (!(await verifyCaptcha(req.body.captcha, req.ip))) return res.status(400).json({ error: 'Robot doğrulaması başarısız.' });

  const generic = { ok: true, message: 'E-posta kayıtlıysa doğrulama kodu gönderildi.' };
  const profile = await findProfile(email);
  if (!profile) return res.json(generic);

  const prev = await latestReset(email);
  if (prev && Date.now() - new Date(prev.created_at).getTime() < COOLDOWN_MS) return res.json(generic);

  await sb.from('password_resets').update({ used: true }).eq('email', email).eq('used', false);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const { data: row, error } = await sb.from('password_resets').insert({
    email, code_hash: h(email + ':' + code), expires_at: new Date(Date.now() + OTP_TTL_MS).toISOString()
  }).select('id').single();
  if (error) throw error;

  try {
    await mailer.sendMail({
      from: MAIL_FROM, to: email, subject: 'Yan Muhasebe - Şifre Sıfırlama Kodu',
      text: `Şifre sıfırlama kodunuz: ${code}\nKod 5 dakika geçerlidir ve tek kullanımlıktır. Bu isteği siz yapmadıysanız bu e-postayı yok sayın.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px">
        <h2 style="margin:0 0 8px;color:#0f172a">Şifre Sıfırlama</h2>
        <p style="color:#475569">Merhaba${profile.full_name ? ' ' + String(profile.full_name).replace(/[<>&]/g, '') : ''}, doğrulama kodunuz:</p>
        <div style="font-size:32px;letter-spacing:8px;font-weight:700;text-align:center;padding:14px;background:#f1f5f9;border-radius:8px;color:#0f172a">${code}</div>
        <p style="color:#64748b;font-size:13px">Kod <b>5 dakika</b> geçerlidir ve tek kullanımlıktır. Bu isteği siz yapmadıysanız bu e-postayı yok sayın.</p></div>`
    });
  } catch (e) {
    console.error('Mail hatası:', e.message);
    await sb.from('password_resets').delete().eq('id', row.id);
    return res.status(502).json({ error: 'E-posta gönderilemedi. Lütfen daha sonra tekrar deneyin.' });
  }
  res.json(generic);
}));

// 2) OTP doğrula (tek kullanımlık) ve kısa ömürlü reset token ver
app.post('/verify-code', strict, wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  const code = String(req.body.code || '').trim();
  const bad = () => res.status(400).json({ error: 'Kod geçersiz veya süresi dolmuş.' });
  if (!email || !/^\d{6}$/.test(code)) return bad();

  const row = await latestReset(email);
  if (!row || row.verified || new Date(row.expires_at) < new Date()) return bad();
  if (row.attempts >= MAX_ATTEMPTS) {
    await sb.from('password_resets').update({ used: true }).eq('id', row.id);
    return res.status(429).json({ error: 'Çok fazla hatalı deneme. Yeni kod isteyin.' });
  }
  if (!safeEq(row.code_hash, h(email + ':' + code))) {
    await sb.from('password_resets').update({ attempts: row.attempts + 1 }).eq('id', row.id);
    return res.status(400).json({ error: 'Kod hatalı.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  const { data: claimed } = await sb.from('password_resets')
    .update({ verified: true, reset_token_hash: h('t:' + token), reset_expires_at: new Date(Date.now() + RESET_TTL_MS).toISOString() })
    .eq('id', row.id).eq('verified', false).select('id');
  if (!claimed || !claimed.length) return bad();
  res.json({ ok: true, resetToken: token });
}));

// 3) Yeni şifreyi kaydet (Supabase Auth şifreyi kendi güvenli hash'i ile saklar)
app.post('/reset-password', strict, wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  const token = String(req.body.resetToken || '');
  const newPassword = String(req.body.newPassword || '');
  const bad = () => res.status(400).json({ error: 'Oturum geçersiz veya süresi dolmuş. Baştan başlayın.' });
  if (!email || !/^[0-9a-f]{64}$/.test(token)) return bad();
  if (!/^\d{6}$/.test(newPassword)) return res.status(400).json({ error: 'Şifre 6 haneli sayı olmalıdır.' });

  const row = await latestReset(email, (q) => q.eq('verified', true));
  if (!row || !row.reset_expires_at || new Date(row.reset_expires_at) < new Date()) return bad();
  if (!safeEq(row.reset_token_hash || '', h('t:' + token))) return bad();

  const { data: claimed } = await sb.from('password_resets').update({ used: true }).eq('id', row.id).eq('used', false).select('id');
  if (!claimed || !claimed.length) return bad();

  const profile = await findProfile(email);
  if (!profile) return bad();
  const { error } = await sb.auth.admin.updateUserById(profile.id, { password: newPassword + CLOUD_PASS_SUFFIX });
  if (error) {
    await sb.from('password_resets').update({ used: false }).eq('id', row.id);
    console.error('Şifre güncelleme hatası:', error.message);
    return res.status(500).json({ error: 'Şifre güncellenemedi. Tekrar deneyin.' });
  }
  res.json({ ok: true });
}));

app.use((err, _req, res, _next) => res.status(err && err.message === 'CORS' ? 403 : 500).json({ error: 'İstek reddedildi.' }));
app.listen(PORT, () => console.log('YanMuhasebe API :' + PORT));
