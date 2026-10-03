# YanMuhasebe Backend (OTP şifre sıfırlama)

## Kurulum (bulutta, bilgisayarınız kapalıyken de çalışır)
1. **Supabase**: `supabase.sql` dosyasını SQL Editor'de çalıştırın.
2. **GitHub**: Bu klasörü bir repoya yükleyin (`.env` yüklenmez).
3. **Render.com** → New → Web Service (veya Blueprint ile `render.yaml`) → repoyu seçin.
   Ortam değişkenlerini `.env.example`'a göre girin. `SUPABASE_SERVICE_ROLE_KEY` ve `RECAPTCHA_SECRET` sadece burada durur.
   (Railway / Fly.io / Cloud Run da aynı şekilde çalışır.)
4. Deploy bitince adresi alın (örn. `https://yanmuhasebe-api.onrender.com`) ve `index.html` içinde
   `window.YM_API_URL = '...'` satırına yazın. `ALLOWED_ORIGINS` içine sitenizin adresini ekleyin.
5. Ücretsiz Render planı boşta uyur; ilk istek ~30 sn sürebilir. Kesintisiz için ücretli plan veya
   https://cron-job.org ile `/health` adresine 10 dakikada bir istek atın.

## Uçlar
- `POST /forgot-password` `{email, captcha}` → 6 haneli kod gönderir (5 dk, tek kullanımlık)
- `POST /verify-code` `{email, code}` → `{resetToken}` (10 dk, 5 hatalı denemede iptal)
- `POST /reset-password` `{email, resetToken, newPassword}` → Supabase Auth'ta şifreyi günceller
- `GET /health`
