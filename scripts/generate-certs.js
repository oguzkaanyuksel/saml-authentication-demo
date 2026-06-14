'use strict';

/**
 * Generates self-signed RSA certificates for SP and IdP (demo only).
 * Run once before starting the application: node scripts/generate-certs.js
 */

const forge = require('node-forge');
const fs    = require('fs');
const path  = require('path');

const CERTS_DIR = path.join(__dirname, '..', 'certs');

function generateCert(commonName) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey    = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);

  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName',       value: commonName },
    { name: 'organizationName', value: 'SAML Demo' },
    { name: 'countryName',      value: 'TR' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true, keyEncipherment: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const certPem       = forge.pki.certificateToPem(cert);
  // Certificate body without PEM headers (used in XML/SAML config)
  const certBody = certPem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace(/\r?\n/g, '')
    .trim();

  return { privateKeyPem, certPem, certBody };
}

function main() {
  if (!fs.existsSync(CERTS_DIR)) {
    fs.mkdirSync(CERTS_DIR, { recursive: true });
  }

  console.log('Generating SP certificates (RSA 2048-bit)...');
  const sp = generateCert('SP - localhost');
  fs.writeFileSync(path.join(CERTS_DIR, 'sp-key.pem'),       sp.privateKeyPem);
  fs.writeFileSync(path.join(CERTS_DIR, 'sp-cert.pem'),      sp.certPem);
  fs.writeFileSync(path.join(CERTS_DIR, 'sp-cert-body.txt'), sp.certBody);
  console.log('  SP certificates saved.');

  console.log('Generating IdP certificates (RSA 2048-bit)...');
  const idp = generateCert('IdP - localhost');
  fs.writeFileSync(path.join(CERTS_DIR, 'idp-key.pem'),       idp.privateKeyPem);
  fs.writeFileSync(path.join(CERTS_DIR, 'idp-cert.pem'),      idp.certPem);
  fs.writeFileSync(path.join(CERTS_DIR, 'idp-cert-body.txt'), idp.certBody);
  console.log('  IdP certificates saved.');

  console.log('\nCertificates generated successfully!');
  console.log(`Location: ${CERTS_DIR}`);
}

main();
