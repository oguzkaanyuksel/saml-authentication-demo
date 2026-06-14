'use strict';

/**
 * SAML Response builder — Identity Provider side.
 *
 * Uses the `samlify` library (industry-standard SAML 2.0) for:
 *   • Parsing inbound AuthnRequests (HTTP-Redirect binding)
 *   • Building and signing outbound SAMLResponse / Assertion (RSA-SHA256)
 *
 * samlify handles XML canonicalization, enveloped-signature insertion and
 * base64 encoding — no manual XML construction is needed.
 */

const samlify = require('samlify');
const crypto  = require('crypto');
const zlib    = require('zlib');
const fs      = require('fs');
const path    = require('path');

// ---------------------------------------------------------------------------
// samlify schema validator (permissive — no external schema downloads)
// ---------------------------------------------------------------------------
samlify.setSchemaValidator({ validate: () => Promise.resolve('ok') });

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CERTS_DIR     = path.join(__dirname, '..', 'certs');
const LOGS_DIR      = path.join(__dirname, '..', 'saml-logs');
const IDP_ENTITY_ID = 'http://localhost:4000';
const SP_ENTITY_ID  = 'http://localhost:3000';
const ACS_URL       = 'http://localhost:3000/auth/saml/callback';

// ---------------------------------------------------------------------------
// samlify entity factories
// ---------------------------------------------------------------------------

/**
 * Creates a samlify IdentityProvider entity from the IdP's key/cert files.
 * The entity is re-created per request so hot-reloaded certs are always used.
 */
function buildIdPEntity() {
  const privateKey = fs.readFileSync(path.join(CERTS_DIR, 'idp-key.pem'),       'utf8');
  const certBody   = fs.readFileSync(path.join(CERTS_DIR, 'idp-cert-body.txt'), 'utf8').trim();

  const metadata = [
    '<?xml version="1.0"?>',
    `<EntityDescriptor entityID="${IDP_ENTITY_ID}"`,
    '  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">',
    '  <IDPSSODescriptor',
    '    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"',
    '    WantAuthnRequestsSigned="false">',
    '    <KeyDescriptor use="signing">',
    '      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">',
    `        <X509Data><X509Certificate>${certBody}</X509Certificate></X509Data>`,
    '      </KeyInfo>',
    '    </KeyDescriptor>',
    `    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${IDP_ENTITY_ID}/saml/sso"/>`,
    '  </IDPSSODescriptor>',
    '</EntityDescriptor>',
  ].join('\n');

  return samlify.IdentityProvider({
    privateKey,
    isAssertionEncrypted:    false,
    wantAuthnRequestsSigned: false,
    metadata,
  });
}

/**
 * Creates a samlify ServiceProvider entity representing our SP.
 * Used by the IdP when parsing AuthnRequests and building responses.
 */
function buildSPEntity() {
  const metadata = [
    '<?xml version="1.0"?>',
    `<EntityDescriptor entityID="${SP_ENTITY_ID}"`,
    '  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">',
    '  <SPSSODescriptor',
    '    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"',
    '    AuthnRequestsSigned="false"',
    '    WantAssertionsSigned="true">',
    `    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${ACS_URL}" index="1"/>`,
    '  </SPSSODescriptor>',
    '</EntityDescriptor>',
  ].join('\n');

  return samlify.ServiceProvider({ metadata });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildAttrStatement(attrs) {
  const items = Object.entries(attrs).map(([name, value]) =>
    `<saml:Attribute Name="${escapeXml(name)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">` +
    `<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" ` +
    `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
    `xsi:type="xs:string">${escapeXml(value)}</saml:AttributeValue>` +
    `</saml:Attribute>`
  ).join('');
  return `<saml:AttributeStatement>${items}</saml:AttributeStatement>`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses an HTTP-Redirect bound SAMLRequest query string and returns
 * { requestId, acsUrl }.
 *
 * Primary path: samlify IdP parser (spec-compliant).
 * Fallback     : manual inflate + regex extraction.
 *
 * @param {object} queryParams - req.query from Express
 * @returns {Promise<{ requestId: string, acsUrl: string }>}
 */
async function parseAuthnRequest(queryParams) {
  try {
    const idp    = buildIdPEntity();
    const sp     = buildSPEntity();
    const result = await idp.parseLoginRequest(sp, 'redirect', { query: queryParams });
    const req    = result.extract.request;
    return {
      requestId: req.id                          || '',
      acsUrl:    req.assertionconsumerserviceurl || ACS_URL,
    };
  } catch (_parseErr) {
    // Fallback: inflate the deflated base64 SAMLRequest manually
    const samlRequest = queryParams.SAMLRequest;
    const decoded     = Buffer.from(samlRequest, 'base64');
    const inflated    = zlib.inflateRawSync(decoded).toString('utf8');
    const idMatch     = inflated.match(/\sID="([^"]+)"/);
    const acsMatch    = inflated.match(/AssertionConsumerServiceURL="([^"]+)"/);
    return {
      requestId: idMatch  ? idMatch[1]  : '',
      acsUrl:    acsMatch ? acsMatch[1] : ACS_URL,
    };
  }
}

/**
 * Builds a signed SAML 2.0 Response and returns it as a base64 string.
 *
 * The Assertion is signed with the IdP's RSA-SHA256 key using samlify's
 * `createLoginResponse` + `customTagReplacement` pipeline.  samlify handles:
 *   • XML canonicalization (exc-c14n#)
 *   • RSA-SHA256 signature computation
 *   • enveloped-signature placement inside the Assertion
 *   • base64 encoding of the final XML
 *
 * The raw XML is also written to saml-logs/ for inspection in the browser.
 *
 * @param {object} opts
 * @param {string} opts.nameID        - Subject NameID (e.g. user e-mail)
 * @param {string} opts.inResponseTo  - AuthnRequest ID to echo back
 * @param {object} opts.attributes    - Flat key/value map of user attributes
 * @returns {Promise<string>} Base64-encoded SAML Response
 */
async function buildSAMLResponse({ nameID, inResponseTo, attributes = {} }) {
  const idp = buildIdPEntity();
  const sp  = buildSPEntity();

  const requestInfo = { extract: { request: { id: inResponseTo } } };
  const user        = { nameID, ...attributes };

  const result = await idp.createLoginResponse(
    sp,
    requestInfo,
    'post',
    user,
    // customTagReplacement: injects all standard + attribute placeholders
    (template) => {
      const id          = `_${crypto.randomUUID().replace(/-/g, '')}`;
      const assertionId = `_${crypto.randomUUID().replace(/-/g, '')}`;
      const now         = new Date().toISOString();
      const notAfter    = new Date(Date.now() + 5 * 60 * 1000).toISOString();

      const authnXml =
        `<saml:AuthnStatement AuthnInstant="${now}">` +
        `<saml:AuthnContext>` +
        `<saml:AuthnContextClassRef>` +
        `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` +
        `</saml:AuthnContextClassRef>` +
        `</saml:AuthnContext>` +
        `</saml:AuthnStatement>`;

      const context = samlify.SamlLib.replaceTagsByValue(template, {
        ID:                                  id,
        AssertionID:                         assertionId,
        Destination:                         ACS_URL,
        Audience:                            SP_ENTITY_ID,
        EntityID:                            SP_ENTITY_ID,
        SubjectRecipient:                    ACS_URL,
        Issuer:                              IDP_ENTITY_ID,
        IssueInstant:                        now,
        AssertionConsumerServiceURL:         ACS_URL,
        StatusCode:                          'urn:oasis:names:tc:SAML:2.0:status:Success',
        ConditionsNotBefore:                 now,
        ConditionsNotOnOrAfter:              notAfter,
        SubjectConfirmationDataNotOnOrAfter: notAfter,
        NameIDFormat:                        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        NameID:                              escapeXml(nameID),
        InResponseTo:                        escapeXml(inResponseTo),
        AuthnStatement:                      authnXml,
        AttributeStatement:                  buildAttrStatement(attributes),
      });

      return { id, context };
    }
  );

  // Decode and persist the signed XML for browser-based inspection
  const signedXml = Buffer.from(result.context, 'base64').toString('utf8');
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName  = `saml-response_${timestamp}_${nameID.replace(/[@.]/g, '_')}.xml`;
  fs.writeFileSync(path.join(LOGS_DIR, fileName), signedXml, 'utf8');

  return result.context; // base64-encoded SAMLResponse
}

module.exports = { parseAuthnRequest, buildSAMLResponse };

