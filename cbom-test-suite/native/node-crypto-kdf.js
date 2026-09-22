/**
 * CBOM Test Suite — node:crypto Key Derivation Functions
 * Tests hkdf, hkdfSync, pbkdf2, pbkdf2Sync, scrypt, scryptSync
 */
const crypto = require('crypto');

// =============================================================================
// HKDF
// =============================================================================
crypto.hkdf('sha256', 'input-key', 'salt', 'info', 32, (err, derivedKey) => {});
crypto.hkdf('sha512', 'input-key', 'salt', 'info', 64, (err, derivedKey) => {});
crypto.hkdf('sha1', 'input-key', 'salt', 'info', 32, (err, derivedKey) => {});

const hkdfResult = crypto.hkdfSync('sha256', 'input-key', 'salt', 'info', 32);
const hkdfResult512 = crypto.hkdfSync('sha512', 'input-key', 'salt', 'info', 64);

// Via variable
const hkdfDigest = 'sha384';
crypto.hkdf(hkdfDigest, 'ikm', 'salt', 'info', 48, () => {});

// =============================================================================
// PBKDF2
// =============================================================================
crypto.pbkdf2('password', 'salt', 100000, 64, 'sha256', (err, key) => {});
crypto.pbkdf2('password', 'salt', 100000, 64, 'sha512', (err, key) => {});
crypto.pbkdf2('password', 'salt', 100000, 64, 'sha1', (err, key) => {});
crypto.pbkdf2('password', 'salt', 100000, 64, 'md5', (err, key) => {});

const pbResult = crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha256');
const pbResult512 = crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');

// Via variable
const pbDigest = 'sha384';
crypto.pbkdf2('pw', 'salt', 10000, 32, pbDigest, () => {});

// =============================================================================
// Scrypt
// =============================================================================
crypto.scrypt('password', 'salt', 64, (err, derivedKey) => {});
crypto.scrypt('password', 'salt', 64, { N: 16384, r: 8, p: 1 }, (err, dk) => {});

const scryptResult = crypto.scryptSync('password', 'salt', 64);
const scryptOpts = crypto.scryptSync('password', 'salt', 64, { N: 16384, r: 8, p: 1 });
