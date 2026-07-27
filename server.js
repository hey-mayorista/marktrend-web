const express = require('express');
const path = require('path');
const { Resend } = require('resend');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json({ limit: '50kb' }));

// Force HTTPS (Render terminates SSL at proxy)
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http') {
    return res.redirect(301, 'https://' + req.hostname + req.originalUrl);
  }
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Gzip/Brotli compression
app.use(compression());

// Rate limiting simple (en memoria — suficiente para un sitio de agencia)
const rateMap = new Map();
const RATE_LIMIT = 5; // max requests
const RATE_WINDOW = 15 * 60 * 1000; // 15 minutes

function rateLimiter(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  
  if (now - entry.start > RATE_WINDOW) {
    entry.count = 1;
    entry.start = now;
  } else {
    entry.count++;
  }
  
  rateMap.set(ip, entry);
  
  if (entry.count > RATE_LIMIT) {
    return res.status(429).json({ error: 'Demasiadas solicitudes. Intentá de nuevo en unos minutos.' });
  }
  next();
}

// Contact form endpoint
app.post('/api/contacto', rateLimiter, async (req, res) => {
  try {
    const data = req.body;
    
    // Honeypot check
    if (data._hp) {
      return res.status(200).json({ ok: true }); // Silent success for bots
    }
    
    // Basic validation
    if (!data.nombre || !data.email || !data.telefono) {
      return res.status(400).json({ error: 'Faltan campos obligatorios.' });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      return res.status(400).json({ error: 'El email no es válido.' });
    }

    const resendKey = process.env.RESEND_API_KEY;
    if (!resendKey) {
      console.error('RESEND_API_KEY not configured');
      return res.status(500).json({ error: 'El servicio de correo no está configurado.' });
    }

    const resend = new Resend(resendKey);

    const subject = `Nueva consulta – ${data.nombre} ${data.apellido || ''}`.trim();
    
    const lines = [
      'NUEVA CONSULTA DESDE MARK-TREND',
      '',
      'DATOS DE CONTACTO',
      `Nombre: ${data.nombre} ${data.apellido || ''}`,
      `Email: ${data.email}`,
      `Teléfono: ${data.telefono}`,
      '',
      'PERFIL DEL NEGOCIO',
      `Rubro: ${data.rubro || '-'}`,
      `Formatos de venta: ${Array.isArray(data.formatos_venta) ? data.formatos_venta.join(', ') : data.formatos_venta || '-'}`,
      `Volumen de venta: ${data.volumen_venta || '-'}`,
      `Tamaño del equipo: ${data.tamano_equipo || '-'}`,
      '',
      'PROBLEMAS IDENTIFICADOS',
      `Problemas: ${Array.isArray(data.problemas) ? data.problemas.join(', ') : data.problemas || '-'}`,
      `Descripción: ${data.descripcion_problema || '-'}`,
      `Estado actual: ${data.estado_solucion || '-'}`,
      '',
      'DATOS ADMINISTRATIVOS',
      `Razón social: ${data.razon_social || '-'}`,
      `CUIT o DNI: ${data.cuit_dni || '-'}`,
      `Dirección: ${data.direccion || '-'}`,
      '',
      `Fecha de envío: ${data.fecha || new Date().toLocaleString('es-AR')}`
    ];

    await resend.emails.send({
      from: process.env.RESEND_FROM || 'MARK-TREND Web <onboarding@resend.dev>',
      to: process.env.CONTACT_RECIPIENT || 'info@marktrend.com.ar',
      subject: subject,
      text: lines.join('\n'),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('Error enviando email:', err);
    res.status(500).json({ error: 'No se pudo enviar el mensaje. Intentá de nuevo.' });
  }
});

// Health check for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Serve static files with aggressive cache headers
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  index: 'index.html',
  maxAge: '31536000000',
  immutable: true,
  setHeaders: (res, filePath) => {
    // HTML files: short cache, revalidate (override maxAge for HTML)
    if (filePath.match(/\.html$/)) {
      res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
    }
  },
}));

// Handle clean URLs — use app.all to support both GET and HEAD
app.all('*', (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(405).end();
  }
  
  // Remove trailing slash if present (except root)
  if (req.path.length > 1 && req.path.endsWith('/')) {
    return res.redirect(301, req.path.slice(0, -1));
  }
  
  // Try to serve index.html from directory
  const filePath = path.join(__dirname, 'public', req.path, 'index.html');
  res.sendFile(filePath, err => {
    if (err) {
      res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
    }
  });
});

app.listen(PORT, () => {
  console.log(`MARK-TREND server running on port ${PORT}`);
});
