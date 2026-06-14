# SAML 2.0 Authentication Demo

Node.js ile yazılmış, tam çalışan bir **SAML 2.0 SP-initiated SSO** demosu.  
Hem **Servis Sağlayıcı (SP)** hem de **Mock Kimlik Sağlayıcı (IdP)** aynı repoda yer almaktadır.

---

## Mimari

```
Kullanıcı (Tarayıcı)
     │
     ▼
┌─────────────────────────────────┐          ┌─────────────────────────────────┐
│  Service Provider (SP)          │          │  Mock Identity Provider (IdP)   │
│  http://localhost:3000          │          │  http://localhost:4000          │
│                                 │          │                                 │
│  GET  /                         │  ──(1)── │  GET  /saml/sso                 │
│  GET  /login  ──AuthnRequest──► │          │  (Login formu gösterilir)       │
│  POST /auth/saml/callback  ◄────│──(2)────│  POST /saml/sso                 │
│  GET  /profile                  │          │  (SAMLResponse oluşturulur)     │
│  GET  /saml/metadata            │          │  GET  /saml/metadata            │
└─────────────────────────────────┘          └─────────────────────────────────┘

(1) HTTP-Redirect Binding  → AuthnRequest (DEFLATE + Base64)
(2) HTTP-POST Binding      → SAMLResponse (Base64, imzalı Assertion)
```

## Klasör Yapısı

```
authentication saml/
├── package.json
├── start.js                   # Her iki sunucuyu başlatır
├── scripts/
│   └── generate-certs.js      # RSA sertifikası üretimi
├── certs/                     # Üretilen sertifikalar (git'e ekleme!)
├── sp/
│   └── server.js              # SP — passport-saml kullanan Express
├── idp/
│   ├── server.js              # Mock IdP — Express
│   └── saml-builder.js        # SAML Response XML oluşturma + imzalama
└── views/
    ├── sp-home.ejs            # SP ana sayfası
    ├── sp-profile.ejs         # Korumalı profil sayfası
    ├── sp-error.ejs           # Hata sayfası
    └── idp-login.ejs          # IdP giriş formu
```

## Kurulum ve Çalıştırma

### 1. Bağımlılıkları yükle

```bash
npm install
```

### 2. Sertifikaları oluştur (tek seferlik)

```bash
npm run setup
# veya
node scripts/generate-certs.js
```

RSA 2048-bit anahtar çiftleri `certs/` klasörüne kaydedilir:
- `sp-key.pem` / `sp-cert.pem` — SP imzalama sertifikası
- `idp-key.pem` / `idp-cert.pem` — IdP imzalama sertifikası

### 3. Uygulamayı başlat

```bash
npm start
```

veya adım 2+3'ü birlikte:

```bash
npm run dev
```

### 4. Tarayıcıda aç

```
http://localhost:3000
```

---

## Demo Hesaplar

| E-posta            | Şifre    | Rol   | Departman    |
|--------------------|----------|-------|--------------|
| admin@demo.com     | admin123 | admin | Bilgi İşlem  |
| user@demo.com      | user123  | user  | Satış        |

---

## SAML Akışı (Adım Adım)

1. **Kullanıcı** `http://localhost:3000` adresini ziyaret eder ve "SAML ile Giriş Yap" butonuna tıklar.
2. **SP** (`passport-saml`) bir `AuthnRequest` XML belgesi oluşturur, DEFLATE sıkıştırır, Base64 kodlar ve kullanıcıyı `http://localhost:4000/saml/sso?SAMLRequest=...` adresine yönlendirir.
3. **IdP** SAMLRequest'i çözer, giriş formunu gösterir.
4. **Kullanıcı** demo kimlik bilgilerini girer.
5. **IdP** kimlik bilgilerini doğrular, bir `saml:Assertion` oluşturur ve **RSA-SHA256** ile imzalar, ardından bunu bir `samlp:Response` içine sarmalar.
6. **IdP** otomatik gönderilen bir HTML form ile SAMLResponse'u Base64 kodlayıp SP'nin ACS (`http://localhost:3000/auth/saml/callback`) adresine **HTTP-POST** olarak iletir.
7. **SP** SAMLResponse'u çözer, IdP'nin public sertifikasıyla imzayı doğrular, oturumu başlatır ve kullanıcıyı `/profile` sayfasına yönlendirir.

---

## Güvenlik Notları

> Bu demo yalnızca **geliştirme/eğitim** amaçlıdır.
> Üretim ortamında aşağıdaki değişiklikler gereklidir:

- `SESSION_SECRET` ortam değişkeninden okunmalı (güçlü, rastgele)
- HTTPS zorunlu olmalı (`cookie.secure: true`)
- Sertifikalar gerçek bir CA'dan temin edilmeli
- Demo kullanıcı listesi yerine gerçek bir dizin (LDAP/AD/veritabanı) kullanılmalı
- `validateInResponseTo: 'always'` ile replay saldırılarına karşı önlem alınmalı (cache gerekmektedir)

---

## Kullanılan Teknolojiler

| Paket | Görev |
|-------|-------|
| `@node-saml/passport-saml` | SP SAML stratejisi |
| `passport` | Authentication middleware |
| `express` | Web framework |
| `express-session` | Oturum yönetimi |
| `xml-crypto` | XML imzalama / doğrulama |
| `node-forge` | RSA sertifika üretimi |
| `ejs` | HTML şablonlama |
| `uuid` | SAML ID üretimi |
