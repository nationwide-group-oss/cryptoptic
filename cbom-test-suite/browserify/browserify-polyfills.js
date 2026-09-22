/**
 * CBOM Test Suite — Browserify Polyfills
 * PARTIALLY COVERED: callee names match node:crypto query but API attribution is wrong.
 * These are npm polyfills for browser environments, not actual node:crypto.
 */

// =============================================================================
// crypto-browserify (~5M/wk) — full node:crypto polyfill
// =============================================================================
const crypto = require('crypto-browserify');

// These all share callee names with node:crypto, so they'll match
// your existing query — but the API should be "crypto-browserify", not "node:crypto"
const hash1 = crypto.createHash('sha256').update('data').digest('hex');
const hash2 = crypto.createHash('md5').update('data').digest('hex');
const hmac1 = crypto.createHmac('sha256', 'key').update('data').digest('hex');

const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

const rand = crypto.randomBytes(32);
crypto.randomFill(Buffer.alloc(16), () => {});

crypto.pbkdf2('password', 'salt', 100000, 64, 'sha512', (err, dk) => {});
const dk = crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');

crypto.createSign('SHA256');
crypto.createVerify('SHA256');

// DH
const dh = crypto.createDiffieHellman(2048);
const ecdh = crypto.createECDH('secp256k1');

// =============================================================================
// randombytes (~10M/wk) — standalone randomBytes polyfill
// =============================================================================
const randomBytes = require('randombytes');

const rb1 = randomBytes(32);
const rb2 = randomBytes(16);
randomBytes(64, (err, buf) => {});

// =============================================================================
// browserify-aes (~6M/wk) — AES polyfill
// =============================================================================
const browserifyAes = require('browserify-aes');

const baCipher = browserifyAes.createCipheriv('aes-256-cbc', key, iv);
const baDecipher = browserifyAes.createDecipheriv('aes-256-cbc', key, iv);
const baGcm = browserifyAes.createCipheriv('aes-256-gcm', key, iv);
const baCtr = browserifyAes.createCipheriv('aes-256-ctr', key, iv);

// =============================================================================
// pbkdf2 (npm) (~6M/wk) — standalone PBKDF2 polyfill
// =============================================================================
const pbkdf2 = require('pbkdf2');

// Async
pbkdf2.pbkdf2('password', 'salt', 100000, 64, 'sha512', (err, dk) => {});
pbkdf2.pbkdf2('password', 'salt', 100000, 32, 'sha256', (err, dk) => {});
pbkdf2.pbkdf2('password', 'salt', 100000, 20, 'sha1', (err, dk) => {});

// Sync
const dk1 = pbkdf2.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');
const dk2 = pbkdf2.pbkdf2Sync('password', 'salt', 100000, 32, 'sha256');

// =============================================================================
// browserify-sign (~5M/wk) — signing polyfill
// =============================================================================
const browserifySign = require('browserify-sign');

const sign = browserifySign.createSign('RSA-SHA256');
sign.update('data');
const signature = sign.sign(privKey);

const verify = browserifySign.createVerify('RSA-SHA256');
verify.update('data');
const valid = verify.verify(pubKey, signature);

// =============================================================================
// browserify-cipher (~5M/wk) — cipher polyfill
// =============================================================================
const browserifyCipher = require('browserify-cipher');

const bcCipher = browserifyCipher.createCipher('aes-256-cbc', 'password');
const bcDecipher = browserifyCipher.createDecipher('aes-256-cbc', 'password');
const bcCipheriv = browserifyCipher.createCipheriv('aes-256-gcm', key, iv);
