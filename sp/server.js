'use strict';

/**
 * Service Provider (SP) Server — Port 3000
 *
 * Uses @node-saml/passport-saml to implement SAML 2.0 SP-initiated SSO.
 *
 * Flow:
 *   1. User visits /login  → SP generates AuthnRequest → redirect to IdP
 *   2. IdP authenticates user → POSTs SAMLResponse to /auth/saml/callback
 *   3. SP validates assertion → logs user in → redirects to /profile
 */

const express    = require('express');
const passport   = require('passport');
const session    = require('express-session');
const bodyParser = require('body-parser');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');

const { Strategy: SamlStrategy } = require('@node-saml/passport-saml');

const app  = express();
const PORT = 3000;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SP_ENTITY_ID  = 'http://localhost:3000';
const IDP_SSO_URL   = 'http://localhost:4000/saml/sso';
const ACS_URL       = 'http://localhost:3000/auth/saml/callback';
const CERTS_DIR     = path.join(__dirname, '..', 'certs');

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(session({
  // Use an environment variable for the secret in production
  secret:            process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   false,  // set to true when behind HTTPS
    sameSite: 'lax',
    maxAge:   8 * 60 * 60 * 1000, // 8 hours
  },
}));

app.use(passport.initialize());
app.use(passport.session());

// ---------------------------------------------------------------------------
// Passport SAML strategy
// ---------------------------------------------------------------------------

function setupPassport() {
  const idpCert      = fs.readFileSync(path.join(CERTS_DIR, 'idp-cert.pem'), 'utf8');
  const spPrivateKey = fs.readFileSync(path.join(CERTS_DIR, 'sp-key.pem'),   'utf8');

  passport.use(
    new SamlStrategy(
      {
        // IdP settings
        entryPoint: IDP_SSO_URL,
        idpCert,

        // SP settings
        issuer:      SP_ENTITY_ID,
        callbackUrl: ACS_URL,
        privateKey:  spPrivateKey,

        // Validation options (relaxed for local demo)
        validateInResponseTo:         'never',
        disableRequestedAuthnContext: true,
        wantAssertionsSigned:         true,
        wantAuthnResponseSigned:      false, // only the Assertion is signed by our IdP
        acceptedClockSkewMs:          5 * 60 * 1000, // 5 minutes
      },
      // SP-initiated verify callback
      (profile, done) => {
        const user = {
          nameID:     profile.nameID,
          email:      profile['email']      || profile.nameID,
          name:       profile['name']       || profile.nameID,
          role:       profile['role']       || 'N/A',
          department: profile['department'] || 'N/A',
        };
        return done(null, user);
      },
      // IdP-initiated verify callback (same mapping)
      (profile, done) => {
        const user = {
          nameID:     profile.nameID,
          email:      profile['email']      || profile.nameID,
          name:       profile['name']       || profile.nameID,
          role:       profile['role']       || 'N/A',
          department: profile['department'] || 'N/A',
        };
        return done(null, user);
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((obj, done) => done(null, obj));
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Home page
app.get('/', (req, res) => {
  res.render('sp-home', { user: req.user || null });
});

// Initiates SAML login (SP-initiated)
app.get('/login', passport.authenticate('saml', {
  failureRedirect: '/login-error',
}));

// ACS — receives the SAMLResponse POST from the IdP
// Middleware: IdP'den gelen ham SAMLResponse'u decode edip diske yazar
app.post('/auth/saml/callback', (req, res, next) => {
  const raw = req.body && req.body.SAMLResponse;
  if (raw) {
    try {
      const xml       = Buffer.from(raw, 'base64').toString('utf8');
      const logsDir   = path.join(__dirname, '..', 'saml-logs');
      if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName  = `sp-received_${timestamp}.xml`;
      fs.writeFileSync(path.join(logsDir, fileName), xml, 'utf8');
    } catch (_) { /* loglama hatası akışı engellemesin */ }
  }
  next();
}, passport.authenticate('saml', { failureRedirect: '/login-error' }),
  (req, res) => {
    const returnTo = req.session.returnTo || '/profile';
    delete req.session.returnTo;
    res.redirect(returnTo);
  }
);

// Protected profile page
app.get('/profile', ensureAuthenticated, (req, res) => {
  res.render('sp-profile', { user: req.user });
});

// Logout
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect('/'));
  });
});

// Login error page
app.get('/login-error', (req, res) => {
  res.status(401).render('sp-error', {
    title:   'Kimlik Doğrulama Başarısız',
    message: 'SAML doğrulaması sırasında bir hata oluştu. Lütfen tekrar deneyin.',
  });
});

// SP SAML metadata
app.get('/saml/metadata', (req, res) => {
  try {
    const strategy = passport._strategy('saml');
    const spCert   = fs.readFileSync(path.join(CERTS_DIR, 'sp-cert.pem'), 'utf8');
    // generateServiceProviderMetadata(decryptionCert, signingCert)
    const metadata = strategy.generateServiceProviderMetadata(null, spCert);
    res.type('application/xml').send(metadata);
  } catch (err) {
    res.status(500).send(`Metadata hatası: ${err.message}`);
  }
});

// ---------------------------------------------------------------------------
// SAML XML Viewer — inspect raw signed assertions in the browser
// ---------------------------------------------------------------------------

const LOGS_DIR = path.join(__dirname, '..', 'saml-logs');

/**
 * GET /saml-viewer
 * Lists available SAML log files and optionally displays one.
 * ?file=<basename>  — renders the named XML file
 */
app.get('/saml-viewer', (req, res) => {
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });

  const files = fs.readdirSync(LOGS_DIR)
    .filter(f => f.endsWith('.xml'))
    .sort()
    .reverse(); // newest first

  let selectedFile = null;
  let xmlContent   = null;

  const requestedFile = req.query.file;
  if (requestedFile) {
    // Sanitise: allow only the basename, no path separators
    const safeName = path.basename(requestedFile);
    const fullPath = path.join(LOGS_DIR, safeName);

    if (files.includes(safeName) && fs.existsSync(fullPath)) {
      selectedFile = safeName;
      xmlContent   = fs.readFileSync(fullPath, 'utf8');
    }
  }

  res.render('saml-viewer', { files, selectedFile, xmlContent });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

function start() {
  setupPassport();
  app.listen(PORT, () => {
    console.log(`[SP]  Service Provider      → http://localhost:${PORT}`);
    console.log(`[SP]  Metadata              → http://localhost:${PORT}/saml/metadata`);
  });
}

module.exports = { start };
