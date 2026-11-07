# License Server — BAYAN Licensed (Python / Faable)

سيرفر التراخيص لـ BAYAN المرخص. يعمل على **Faable Deploy كـ Python Service** عبر `main.py + requirements.txt` كما تستخدمه أنت.

## ما يفعله
- إنشاء/إدارة المنتجات (bayan وغيره) وحد أجهزة مستقل لكل ترخيص
- تفعيل أكواد 15 حرف وتوليد grants موقعة Ed25519 (مهلة offline 7 أيام)
- تجميد/إلغاء تراخيص وأجهزة مع رسالة مهذبة (لا يحذف بيانات المستخدم)
- طلبات Telegram: المستخدم يطلب من البوت → أنت توافق من Admin → البوت يرسل الكود تلقائياً
- واجهات Admin محمية بـ Faable Auth (JWT RS256 + JWKS) — فقط `sub` المصرح له في `ADMIN_SUBJECTS`
- سجل تدقيق كامل (audit) لكل إجراء

## المتطلبات
- Python 3.11+ (Faable يوفره)
- PostgreSQL مستضاف (Neon / Supabase / إلخ) — Faable filesystem مؤقت، لا تضع SQLite
- Faable Auth Tenant (Issuer, Audience, JWKS)
- Telegram Bot (من BotFather)

## 1) إنشاء المفاتيح (مرة واحدة على كمبيوترك)

```bash
cd server-python
pip install cryptography
python generate_keys.py
```

سيطبع:
```
GRANT_PRIVATE_KEY_B64=...  (للسيرفر فقط)
GRANT_PUBLIC_KEY_B64=...   (للموبايل - آمن)
GRANT_KEY_ID=2026-01
ACTIVATION_CODE_PEPPER=... (32+ حرف)
TELEGRAM_WEBHOOK_SECRET=...
```
انسخهم إلى Faable Variables لاحقاً. **لا ترفع `generated_keys.env` إلى GitHub.**

## 2) GitHub — إنشاء المستودع

```bash
cd server-python
git init
git add main.py requirements.txt sql/001_initial.sql generate_keys.py .gitignore README.md .env.example
git commit -m "License server Python for Faable"
git branch -M main
git remote add origin https://github.com/YOUR_NAME/bayan-license-server.git
git push -u origin main
```

> لا تضف `.env` أو `generated_keys.env` — الأسرار في Faable فقط.

## 3) Faable Deploy — الربط

1. في Faable: New Service → Connect GitHub → اختر `bayan-license-server`
2. **Runtime:** Python, **Install:** `pip install -r requirements.txt`, **Start:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. أضف كل Variables من `.env.example` (انسخ ناتج `generate_keys.py` + DATABASE_URL + Faable + TELEGRAM_BOT_TOKEN)
4. Deploy → افتح `https://YOUR-APP.faable.app/healthz` → يجب أن ترجع `{ok:true}`

## 4) قاعدة البيانات

بعد ضبط `DATABASE_URL` في Faable، شغّل Migration مرة واحدة من كمبيوترك:

```bash
psql "$DATABASE_URL" -f sql/001_initial.sql
# أو عبر أي عميل PostgreSQL — الملف idempotent (آمن تكراره)
```

`001_initial.sql` ينشئ جداول: `products`, `licenses`, `installations`, `activation_requests`, `audit_events`

## 5) Faable Auth

1. في Faable Auth: سجّل API بـ Audience ثابت (مثلاً `https://api.bayan.licenses`)
2. انسخ **Issuer** و **JWKS URL** الحقيقيين من Discovery وضعهم في Variables
3. أنشئ **Native Client** للـ Admin App (Authorization Code + PKCE) بدون Secret
4. أضف Redirect: `com.licensecontrol.admin:/oauthredirect`
5. ضع `sub` حسابك في `ADMIN_SUBJECTS` (فواصل إذا أكثر من واحد)

## 6) Telegram Bot

1. افتح BotFather → `/newbot` → انسخ التوكن إلى `TELEGRAM_BOT_TOKEN` في Faable
2. بعد نشر السيرفر، اضبط Webhook:
```bash
BOT_TOKEN="123:ABC"
API_URL="https://YOUR-APP.faable.app"
SECRET="قيمة TELEGRAM_WEBHOOK_SECRET نفسها"

curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/setWebhook" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"$API_URL/webhooks/telegram\",\"secret_token\":\"$SECRET\",\"drop_pending_updates\":true}"
```
3. أضف المنتج من Admin App → سيظهر في البوت

## 7) متغيرات البيئة الكاملة

انسخ من `.env.example`:

| المتغير | أين يوضع | وصف |
|---|---|---|
| DATABASE_URL | Faable | PostgreSQL (sslmode=require) |
| ACTIVATION_CODE_PEPPER | Faable | 32+ حرف عشوائي |
| GRANT_PRIVATE_KEY_B64 | Faable | خاص — للسيرفر فقط |
| GRANT_PUBLIC_KEY_B64 | Faable + Flutter | عام — يُدمج مشفر في APK |
| GRANT_KEY_ID | Faable | مثل 2026-01 |
| FAABLE_AUTH_ISSUER | Faable | من Faable Auth |
| FAABLE_AUTH_AUDIENCE | Faable | API Audience |
| FAABLE_AUTH_JWKS_URL | Faable | JWKS URL |
| ADMIN_SUBJECTS | Faable | sub المسموح له |
| TELEGRAM_BOT_TOKEN | Faable | من BotFather |
| TELEGRAM_WEBHOOK_SECRET | Faable | سلسلة عشوائية |
| TELEGRAM_API_BASE | Faable | اتركه https://api.telegram.org |

## اختبار سريع بعد النشر

```bash
# إنشاء منتج (JWT من Faable)
curl -X POST https://YOUR-APP.faable.app/v1/admin/products \
  -H "Authorization: Bearer $FAABLE_JWT" \
  -H "Content-Type: application/json" \
  -d '{"slug":"bayan","name":"BAYAN","packageName":"com.bayanstudio.bayan.licensed","offlineGraceSeconds":604800}'

# إنشاء ترخيص
curl -X POST https://YOUR-APP.faable.app/v1/admin/licenses \
  -H "Authorization: Bearer $FAABLE_JWT" \
  -H "Content-Type: application/json" \
  -d '{"productId":"UUID","maxInstallations":1,"label":"اختبار"}'
# → يعيد code مثل ABCDE-FGHIJ-KLMNO

# جرب تفعيل (من الموبايل أو curl)
curl -X POST https://YOUR-APP.faable.app/v1/activate \
  -H "Content-Type: application/json" \
  -d '{"product":"bayan","installationId":"test-device-1234567890","code":"ABCDE-FGHIJ-KLMNO"}'
```

## ملاحظات أمان

- لا تضع `GRANT_PRIVATE_KEY_B64` أو `TELEGRAM_BOT_TOKEN` أو `DATABASE_URL` في Git/APK
- سجل audit يخزن hint فقط للكود، لا يخزن الكود الكامل أو التوكن
- Telegram user id يُمحى بعد التسليم الناجح — راجع `/privacy`

## استكشاف الأخطاء

- `healthz` لا يعمل → راجع PORT و HOST=0.0.0.0 في Faable Logs
- `401/403 Admin` → تأكد من Issuer/Audience/JWKS والـ sub في ADMIN_SUBJECTS
- Telegram لا يرسل → تأكد من Webhook + Secret متطابقين + المنتج active
