'use strict';

/**
 * Starts both the Service Provider (SP) and the Mock Identity Provider (IdP).
 * Run: node start.js
 */

const fs   = require('fs');
const path = require('path');

const CERTS_DIR = path.join(__dirname, 'certs');

// Ensure certificates have been generated
const requiredFiles = [
  'sp-key.pem', 'sp-cert.pem', 'sp-cert-body.txt',
  'idp-key.pem', 'idp-cert.pem', 'idp-cert-body.txt',
];

const missing = requiredFiles.filter(f => !fs.existsSync(path.join(CERTS_DIR, f)));

if (missing.length > 0) {
  console.error('\n[ERROR] Sertifikalar bulunamadı. Önce şunu çalıştırın:');
  console.error('        node scripts/generate-certs.js\n');
  console.error('        Ya da: npm run dev   (setup + start birlikte)\n');
  process.exit(1);
}

console.log('='.repeat(55));
console.log('  SAML 2.0 Authentication Demo');
console.log('='.repeat(55));
console.log('');

const idp = require('./idp/server');
const sp  = require('./sp/server');

idp.start();
sp.start();

console.log('');
console.log('  Uygulamayı açın → http://localhost:3000');
console.log('');
console.log('  Demo Hesaplar:');
console.log('    admin@demo.com  /  admin123  (Admin)');
console.log('    user@demo.com   /  user123   (Kullanıcı)');
console.log('');
console.log('  Çıkmak için: Ctrl+C');
console.log('='.repeat(55));
