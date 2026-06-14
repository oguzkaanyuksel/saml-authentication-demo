'use strict';

/**
 * Identity Provider (IdP) Server — Port 4000
 *
 * Implements SAML 2.0 SSO:
 *   • HTTP-Redirect binding  — inbound AuthnRequests from the SP
 *   • HTTP-POST binding      — outbound SAMLResponse to the SP ACS
 *
 * The `samlify` library (via saml-builder.js) handles request parsing and
 * signed-response generation.  No manual XML construction here.
 *
 * Demo users:
 *   admin@demo.com / admin123
 *   user@demo.com  / user123
 */

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const fs         = require('fs');

const { parseAuthnRequest, buildSAMLResponse } = require('./saml-builder');

const app  = express();
const PORT = 4000;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const IDP_ENTITY_ID = 'http://localhost:4000';
const SP_ENTITY_ID  = 'http://localhost:3000';
const ACS_URL       = 'http://localhost:3000/auth/saml/callback';

const CERTS_DIR = path.join(__dirname, '..', 'certs');
const LOGS_DIR  = path.join(__dirname, '..', 'saml-logs');

// Demo user store — in production use a real directory (LDAP/AD/DB)
const DEMO_USERS = {
  'admin@demo.com': {
    password:   'admin123',
    name:       'Admin Kullanıcı',
    role:       'admin',
    department: 'Bilgi İşlem',
  },
  'user@demo.com': {
    password:   'user123',
    name:       'Normal Kullanıcı',
    role:       'user',
    department: 'Satış',
  },
};

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(bodyParser.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * GET /saml/metadata
 * Returns the IdP SAML metadata XML.
 */
app.get('/saml/metadata', (req, res) => {
  const certBody = fs.readFileSync(path.join(CERTS_DIR, 'idp-cert-body.txt'), 'utf8');

  const metadata = `<?xml version="1.0"?>
<EntityDescriptor entityID="${IDP_ENTITY_ID}"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${certBody}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${IDP_ENTITY_ID}/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

  res.type('application/xml').send(metadata);
});

/**
 * GET /saml/sso
 * Receives the HTTP-Redirect bound AuthnRequest from the SP.
 * Parsed with samlify; displays the login form.
 */
app.get('/saml/sso', async (req, res) => {
  const { SAMLRequest, RelayState } = req.query;

  if (!SAMLRequest) {
    return res.status(400).send('Missing SAMLRequest parameter');
  }

  let requestId = '';
  let acsUrl    = ACS_URL;

  try {
    const parsed = await parseAuthnRequest(req.query);
    requestId = parsed.requestId;
    acsUrl    = parsed.acsUrl;
  } catch (err) {
    console.error('[IdP] Error parsing SAMLRequest:', err.message);
    return res.status(400).send('Invalid SAMLRequest');
  }

  res.render('idp-login', {
    relayState: RelayState || '',
    requestId,
    acsUrl,
    error: null,
  });
});

/**
 * POST /saml/sso
 * Handles login form submission.
 * On success, builds a signed SAMLResponse via samlify and auto-submits it to the SP ACS.
 */
app.post('/saml/sso', async (req, res) => {
  const { email, password, requestId, relayState, acsUrl } = req.body;

  const targetAcs = acsUrl || ACS_URL;

  // Validate credentials
  const user = DEMO_USERS[email];
  if (!user || user.password !== password) {
    return res.render('idp-login', {
      relayState: relayState || '',
      requestId:  requestId  || '',
      acsUrl:     targetAcs,
      error:      'Geçersiz e-posta veya şifre.',
    });
  }

  let samlResponse;
  try {
    // buildSAMLResponse uses samlify to sign the Assertion (RSA-SHA256)
    samlResponse = await buildSAMLResponse({
      nameID:       email,
      inResponseTo: requestId || '',
      attributes: {
        email,
        name:       user.name,
        role:       user.role,
        department: user.department,
      },
    });
  } catch (err) {
    console.error('[IdP] Error building SAMLResponse:', err.message);
    return res.status(500).send('SAML response generation failed');
  }

  // HTTP-POST binding: return an auto-submitting HTML form
  const relayStateField = relayState
    ? `<input type="hidden" name="RelayState" value="${escapeHtml(relayState)}">`
    : '';

  res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <title>SAML Response Gönderiliyor…</title>
  <style>
    body { font-family: sans-serif; display:flex; justify-content:center;
           align-items:center; height:100vh; background:#f0f4f8; }
    .card { background:#fff; padding:2rem; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,.1); text-align:center; }
    .spinner { width:40px; height:40px; border:4px solid #e2e8f0;
               border-top-color:#4299e1; border-radius:50%;
               animation:spin .8s linear infinite; margin:1rem auto; }
    @keyframes spin { to { transform:rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <p>Kimlik doğrulandı, yönlendiriliyor…</p>
    <form id="samlForm" method="POST" action="${escapeHtml(targetAcs)}">
      <input type="hidden" name="SAMLResponse" value="${samlResponse}">
      ${relayStateField}
      <noscript>
        <p>JavaScript devre dışı. Lütfen devam etmek için tıklayın:</p>
        <input type="submit" value="Devam Et">
      </noscript>
    </form>
  </div>
  <script>document.getElementById('samlForm').submit();</script>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

function start() {
  app.listen(PORT, () => {
    console.log(`[IdP] Mock Identity Provider → http://localhost:${PORT}`);
    console.log(`[IdP] Metadata              → http://localhost:${PORT}/saml/metadata`);
  });
}

module.exports = { start };
