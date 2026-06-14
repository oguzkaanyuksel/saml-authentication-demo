'use strict';
// One-shot test: build a SAML response with samlify and verify its Assertion signature.
const { buildSAMLResponse } = require('./idp/saml-builder');
const { SignedXml } = require('@node-saml/node-saml/node_modules/xml-crypto');
const xpath = require('xpath');
const { DOMParser } = require('@xmldom/xmldom');
const fs = require('fs'), path = require('path');

const cert = fs.readFileSync(path.join('certs', 'idp-cert.pem'), 'utf8');

(async () => {
  const b64 = await buildSAMLResponse({
    nameID:       'admin@demo.com',
    inResponseTo: '_testid001',
    attributes:   { email: 'admin@demo.com', role: 'admin' },
  });

  const fullXml = Buffer.from(b64, 'base64').toString('utf8');
  const doc = new DOMParser().parseFromString(fullXml);

  const assertions = xpath.select("//*[local-name(.)='Assertion']", doc);
  console.log('Assertions found:', assertions.length);

  const assertion = assertions[0];
  const signatures = xpath.select("./*[local-name(.)='Signature']", assertion);
  console.log('Signatures in Assertion:', signatures.length);

  if (signatures.length === 0) {
    console.error('FAIL: No signature found inside Assertion');
    process.exit(1);
  }

  const sig = new SignedXml();
  sig.publicCert = cert;
  sig.loadSignature(signatures[0]);
  const valid = sig.checkSignature(fullXml);
  console.log('Signature valid:', valid);
  if (!valid) {
    console.error('Validation errors:', sig.validationErrors);
    process.exit(1);
  }
  console.log('PASS: samlify-generated Assertion signature is cryptographically valid');
})();
