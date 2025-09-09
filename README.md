# Portal Backend API

Portal Yurt Dışı Eğitim ve Vize Danışmanlık admin paneli için güvenli backend API.

## 🚀 Hızlı Başlangıç

### 1. Kurulum
```bash
# Dependencies yükle
npm install

# Environment variables ayarla
cp env.example .env
# .env dosyasını düzenle (JWT_SECRET ve FRONTEND_URL)

# Development server başlat
npm run dev

# Production server başlat
npm start
```

### 2. Environment Variables (.env)
```bash
NODE_ENV=production
PORT=3001
JWT_SECRET=your-super-secure-jwt-secret-minimum-32-characters-long
FRONTEND_URL=https://your-frontend-domain.com
```

### 3. API Endpoints

#### POST `/api/admin/login`
Admin giriş
```json
// Request
{
  "password": "portal2024"
}

// Response
{
  "success": true,
  "expiresIn": 7200
}
```

#### POST `/api/admin/change-password`
Şifre değiştirme (authentication gerekli)
```json
// Request
{
  "currentPassword": "portal2024",
  "newPassword": "NewSecurePassword123!"
}

// Response
{
  "success": true,
  "message": "Şifre başarıyla değiştirildi"
}
```

#### POST `/api/admin/logout`
Çıkış yapma
```json
// Response
{
  "success": true,
  "message": "Başarıyla çıkış yapıldı"
}
```

#### GET `/api/admin/verify`
Token doğrulama (authentication gerekli)
```json
// Response
{
  "success": true,
  "admin": {...},
  "message": "Token geçerli"
}
```

#### GET `/api/health`
Sunucu durumu
```json
// Response
{
  "success": true,
  "message": "Portal Backend API çalışıyor",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## 🔒 Güvenlik Özellikleri

- ✅ bcrypt password hashing (12 rounds)
- ✅ JWT tokens (2 saat expiry)
- ✅ HttpOnly cookies
- ✅ Rate limiting (5 deneme/15 dakika)
- ✅ CORS protection
- ✅ Helmet security headers
- ✅ Strong password validation
- ✅ Input sanitization

## 📦 Deployment

### Railway
```bash
railway login
railway init
railway up

# Environment variables set et:
railway variables set JWT_SECRET=your-secret
railway variables set FRONTEND_URL=https://your-frontend.com
railway variables set NODE_ENV=production
```

### Heroku
```bash
heroku create your-app-name
git push heroku main

heroku config:set JWT_SECRET=your-secret
heroku config:set FRONTEND_URL=https://your-frontend.com
heroku config:set NODE_ENV=production
```

### VPS
```bash
# PM2 ile production
npm install -g pm2
pm2 start server.js --name "portal-backend"
pm2 startup
pm2 save

# Environment variables
export JWT_SECRET=your-secret
export FRONTEND_URL=https://your-frontend.com
export NODE_ENV=production
```

## ⚠️ Güvenlik Notları

1. **JWT_SECRET**: Minimum 32 karakter, random string kullanın
2. **Default Password**: İlk giriş sonrası mutlaka değiştirin (portal2024)
3. **HTTPS**: Production'da HTTPS zorunlu
4. **CORS**: FRONTEND_URL'yi doğru ayarlayın
5. **Rate Limiting**: Brute force koruması aktif
6. **Logs**: Failed attempts loglanıyor

## 🧪 Test

```bash
# Health check
curl http://localhost:3001/api/health

# Login test
curl -X POST http://localhost:3001/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"password":"portal2024"}'
```

## 📊 Monitoring

- Login attempts loglanıyor
- IP adresleri kaydediliyor
- Rate limiting uyarıları
- Authentication errors

## 🔄 Production Checklist

- [ ] JWT_SECRET güçlü ve unique
- [ ] NODE_ENV=production
- [ ] FRONTEND_URL doğru
- [ ] HTTPS certificate yüklü
- [ ] Default password değiştirildi
- [ ] Rate limiting test edildi
- [ ] CORS ayarları doğru
- [ ] Monitoring kuruldu
