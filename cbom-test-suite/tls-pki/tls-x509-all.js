/**
 * CBOM Test Suite — TLS / X.509 / PKI
 * NOT COVERED by current queries.
 */

// =============================================================================
// node:tls — TLS configuration
// =============================================================================
const tls = require('tls');
const fs = require('fs');

// TLS server with cipher suite and version constraints
const server = tls.createServer({
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem'),
  ca: [fs.readFileSync('ca-cert.pem')],
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256',
  ecdhCurve: 'P-256:P-384:P-521',
  honorCipherOrder: true,
  requestCert: true,
  rejectUnauthorized: true,
}, (socket) => {
  console.log(socket.getCipher());
  console.log(socket.getProtocol());
  console.log(socket.getPeerCertificate());
});

// TLS client
const client = tls.connect(443, 'example.com', {
  ca: [fs.readFileSync('ca-cert.pem')],
  minVersion: 'TLSv1.2',
  rejectUnauthorized: true,
  servername: 'example.com',
  checkServerIdentity: (hostname, cert) => {
    return tls.checkServerIdentity(hostname, cert);
  }
});

// Secure context
const ctx = tls.createSecureContext({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
});

// Explicit TLS 1.3 cipher suites
const server13 = tls.createServer({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
  minVersion: 'TLSv1.3',
});

// Insecure TLS configurations (should be flagged)
const insecureServer = tls.createServer({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  minVersion: 'TLSv1',        // Insecure: TLS 1.0
  ciphers: 'RC4-SHA:DES-CBC3-SHA', // Insecure ciphers
  rejectUnauthorized: false,   // No cert validation
});

// =============================================================================
// node:https — HTTPS server (delegates to TLS)
// =============================================================================
const https = require('https');

const httpsServer = https.createServer({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  minVersion: 'TLSv1.2',
  ciphers: 'ECDHE-RSA-AES128-GCM-SHA256',
}, (req, res) => {
  res.end('OK');
});

const httpsAgent = new https.Agent({
  ca: fs.readFileSync('ca.pem'),
  minVersion: 'TLSv1.2',
  ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  rejectUnauthorized: true,
});

// =============================================================================
// @peculiar/x509 (~200k/wk) — modern X.509 library
// =============================================================================
import * as x509 from '@peculiar/x509';

// Generate self-signed certificate using WebCrypto
const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);

const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  name: 'CN=Test',
  notBefore: new Date(),
  notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  keys: keys,
  signingAlgorithm: alg,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ],
});

// RSA certificate
const rsaAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };
const rsaKeys = await crypto.subtle.generateKey(rsaAlg, true, ['sign', 'verify']);
const rsaCert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '02',
  name: 'CN=RSA Test',
  notBefore: new Date(),
  notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  keys: rsaKeys,
  signingAlgorithm: rsaAlg,
});

// CSR
const csr = await x509.Pkcs10CertificateRequestGenerator.create({
  name: 'CN=My App',
  keys: keys,
  signingAlgorithm: alg,
});

// Parse certificate
const parsed = new x509.X509Certificate(pemString);
console.log(parsed.publicKey);
console.log(parsed.signatureAlgorithm);
console.log(parsed.serialNumber);

// Certificate chain validation
const chain = new x509.X509ChainBuilder({ certificates: [intermediateCert] });
const chainResult = await chain.build(leafCert);

// CRL
const crl = await x509.X509CrlGenerator.create({
  issuer: caCert.subject,
  thisUpdate: new Date(),
  nextUpdate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  entries: [{ serialNumber: '03', revocationDate: new Date() }],
  signingKey: caPrivKey,
  signingAlgorithm: alg,
});

// =============================================================================
// selfsigned (~4M/wk) — self-signed cert generation
// =============================================================================
const selfsigned = require('selfsigned');

// Default (RSA 1024 — insecure default!)
const defaultCert = selfsigned.generate();

// With options
const attrs = [{ name: 'commonName', value: 'example.com' }];
const opts = {
  keySize: 2048,
  algorithm: 'sha256',
  days: 365,
  extensions: [{ name: 'subjectAltName', altNames: [{ type: 2, value: 'example.com' }] }]
};
const customCert = selfsigned.generate(attrs, opts);

// RSA 4096
const strongCert = selfsigned.generate(attrs, { keySize: 4096, algorithm: 'sha512' });

// EC (if supported)
const ecCert = selfsigned.generate(attrs, {
  keySize: '256',
  algorithm: 'sha256',
  pkcs7: true
});
