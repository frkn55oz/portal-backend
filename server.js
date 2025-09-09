const express = require('express');
const crypto = require('crypto-js');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Güvenlik middleware
app.use(helmet());
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));

// CORS ayarları - Production ve development
const allowedOrigins = [
  'http://localhost:5174',  // Development
  'https://localhost:5174', // Development HTTPS
  process.env.FRONTEND_URL, // Production
  'https://portalvizedanismanlik.com', // GoDaddy domain (GERÇEK DOMAIN'İNİ YAZ)
  'https://portalvizedanismanlik.com'   // HTTP fallback
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// Rate limiting - Brute force koruması
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 5, // maksimum 5 deneme
  message: { 
    success: false,
    error: 'Çok fazla giriş denemesi. 15 dakika bekleyin.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Varsayılan admin şifresi hash'i (portal2024)
// ⚠️ Production'da mutlaka değiştirin!
let adminPasswordHash = null; // İlk giriş için plain text kontrol

console.log('🔐 Default admin password: portal2024 (Mutlaka değiştirin!)');

// JWT secret kontrol
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('❌ JWT_SECRET environment variable eksik veya çok kısa! (min 32 karakter)');
  process.exit(1);
}

// Middleware: JWT token doğrulama (Header tabanlı)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Token bulunamadı'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Geçersiz token'
      });
    }
    req.admin = decoded;
    next();
  });
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Portal Backend API çalışıyor',
    timestamp: new Date().toISOString()
  });
});

// Admin login endpoint
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Şifre gerekli'
      });
    }

    console.log('🔍 Login attempt from IP:', req.ip);

    // Şifre kontrolü - ilk giriş için plain text, sonra hash
    const isValid = adminPasswordHash ? 
      crypto.SHA256(password).toString() === adminPasswordHash : 
      password === 'portal2024';
    
    if (!isValid) {
      console.log('❌ Invalid password attempt from IP:', req.ip);
      return res.status(401).json({
        success: false,
        error: 'Geçersiz şifre'
      });
    }

    console.log('✅ Successful login from IP:', req.ip);

    // JWT token oluştur
    const token = jwt.sign(
      { 
        admin: true,
        loginTime: Date.now(),
        ip: req.ip
      },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Token'ı response'da gönder (cookie yerine)
    res.json({
      success: true,
      token: token,
      expiresIn: 7200
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Sunucu hatası'
    });
  }
});

// Şifre değiştirme endpoint
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Mevcut şifre ve yeni şifre gerekli'
      });
    }

    // Mevcut şifre kontrolü - ilk giriş için plain text, sonra hash
    const isCurrentValid = adminPasswordHash ? 
      crypto.SHA256(currentPassword).toString() === adminPasswordHash : 
      currentPassword === 'portal2024';
    if (!isCurrentValid) {
      console.log('❌ Wrong current password from IP:', req.ip);
      return res.status(401).json({
        success: false,
        error: 'Mevcut şifre yanlış'
      });
    }

    // Yeni şifre validasyonu (güçlü şifre)
    if (newPassword.length < 12) {
      return res.status(400).json({
        success: false,
        error: 'Şifre en az 12 karakter olmalıdır'
      });
    }

    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/g.test(newPassword)) {
      return res.status(400).json({
        success: false,
        error: 'Şifre en az bir büyük harf, küçük harf, rakam ve özel karakter (@$!%*?&) içermelidir'
      });
    }

    // Yeni şifreyi hashle (SHA256 - güvenli)
    const newHash = crypto.SHA256(newPassword).toString();
    adminPasswordHash = newHash;

    console.log('✅ Password changed successfully from IP:', req.ip);

    // Tüm oturumları sonlandır (yeniden giriş zorunlu)
    res.clearCookie('admin_token');

    res.json({
      success: true,
      message: 'Şifre başarıyla değiştirildi. Lütfen yeniden giriş yapın.'
    });

  } catch (error) {
    console.error('❌ Change password error:', error);
    res.status(500).json({
      success: false,
      error: 'Şifre değiştirme başarısız'
    });
  }
});

// Logout endpoint (Token tabanlı - client'da token silinir)
app.post('/api/admin/logout', (req, res) => {
  console.log('🚪 Logout from IP:', req.ip);
  res.json({ 
    success: true,
    message: 'Başarıyla çıkış yapıldı'
  });
});

// Token doğrulama endpoint (frontend için)
app.get('/api/admin/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    admin: req.admin,
    message: 'Token geçerli'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint bulunamadı'
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Sunucu hatası'
  });
});

// Sunucuyu başlat
app.listen(PORT, () => {
  console.log('');
  console.log('🚀 Portal Backend API Started!');
  console.log('=====================================');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:5173'}`);
  console.log(`🔐 Default Password: portal2024 (MUTLAKA DEĞİŞTİRİN!)`);
  console.log('=====================================');
  console.log('');
  
  if (process.env.NODE_ENV !== 'production') {
    console.log('⚠️  DEVELOPMENT MODE - Production için NODE_ENV=production ayarlayın');
  }
  
  if (!process.env.FRONTEND_URL) {
    console.log('⚠️  FRONTEND_URL environment variable ayarlanmamış');
  }
});
