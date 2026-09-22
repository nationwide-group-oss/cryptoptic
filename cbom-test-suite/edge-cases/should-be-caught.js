/**
 * CBOM Test Suite — Patterns That SHOULD Be Caught
 * Tests the existing three-tier argument resolution heuristics.
 * These verify your property heuristic and array-iteration heuristic work.
 */
const crypto = require('crypto');

// =============================================================================
// TIER 1: Direct string literal (should always work)
// =============================================================================
crypto.createHash('sha256').update('data').digest('hex');
crypto.createCipheriv('aes-256-gcm', key, iv);
crypto.createHmac('sha512', 'key').update('data').digest('hex');
crypto.generateKeyPairSync('ed25519');

// =============================================================================
// TIER 1: Local-flow variable assignment (should work via flow analysis)
// =============================================================================
const hashAlgo = 'sha256';
crypto.createHash(hashAlgo).update('data').digest('hex');

let cipherAlgo = 'aes-256-cbc';
crypto.createCipheriv(cipherAlgo, key, iv);

const hmacAlgo = 'sha384';
crypto.createHmac(hmacAlgo, 'key').update('data').digest('hex');

// Multiple variable hops (may or may not resolve depending on flow depth)
const a = 'sha256';
const b = a;
crypto.createHash(b).update('data').digest('hex');

// =============================================================================
// TIER 2: Object property heuristic
// Tests the getArgValueByPropertyHeuristic predicate
// =============================================================================

// Pattern: object with property matching variable name used as argument
const configs = [
  { name: 'aes-128-cbc', keyLen: 16 },
  { name: 'aes-256-gcm', keyLen: 32 },
  { name: 'chacha20-poly1305', keyLen: 32 },
];

configs.forEach(({ name }) => {
  crypto.createCipheriv(name, crypto.randomBytes(32), crypto.randomBytes(16));
});

// Single object variant
const hashConfig = { algorithm: 'sha512', encoding: 'hex' };
// Note: this pattern requires the variable name 'algorithm' to match a property name
// in an object in the same file. The property heuristic looks for objects with a
// property whose name matches the variable reference.

// =============================================================================
// TIER 3: Array iteration heuristic
// Tests the getArgValueByArrayIterationHeuristic predicate
// =============================================================================

// forEach
['sha256', 'sha512', 'sha3-256'].forEach(algo => {
  crypto.createHash(algo).update('data').digest('hex');
});

// map
['aes-128-cbc', 'aes-256-cbc', 'aes-256-gcm'].map(cipher => {
  return crypto.createCipheriv(cipher, crypto.randomBytes(32), crypto.randomBytes(16));
});

// filter (tests if filter is in the method list)
['ed25519', 'ed448', 'rsa', 'dsa'].filter(type => {
  crypto.generateKeyPairSync(type);
  return true;
});

// Array stored in variable first (should work with flow resolution on receiver)
const hashAlgos = ['md5', 'sha1', 'sha256', 'sha512'];
hashAlgos.forEach(alg => {
  crypto.createHash(alg).update('data').digest('hex');
});

// Key types via forEach
const keyTypes = ['rsa', 'ec', 'ed25519', 'x25519'];
keyTypes.forEach(type => {
  crypto.generateKeyPairSync(type);
});

// ECDH curves via forEach
const curves = ['secp256k1', 'prime256v1', 'secp384r1'];
curves.forEach(curve => {
  crypto.createECDH(curve);
});

// DH group names
const groups = ['modp14', 'modp15', 'modp16'];
groups.forEach(group => {
  crypto.getDiffieHellman(group);
});

// HMAC algorithms
['md5', 'sha1', 'sha256', 'sha512'].forEach(digest => {
  crypto.createHmac(digest, 'key').update('data').digest('hex');
});

// Nested: array iteration with the crypto call
['sha256', 'sha384', 'sha512'].forEach(hashAlg => {
  crypto.hkdf(hashAlg, 'ikm', 'salt', 'info', 32, () => {});
});

// PBKDF2 digests
['sha1', 'sha256', 'sha512'].forEach(digest => {
  crypto.pbkdf2('pw', 'salt', 10000, 32, digest, () => {});
});

// =============================================================================
// WebCrypto — tests that should be caught
// =============================================================================

// String-form algorithm
crypto.subtle.digest('SHA-256', new Uint8Array([1]));
crypto.subtle.encrypt('AES-GCM', key, data);

// Object-form algorithm (should be resolved by getWebCryptoAlgoName)
crypto.subtle.digest({ name: 'SHA-512' }, new Uint8Array([1]));
crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, data);
crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, ecKey, data);
crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);

// Object via variable (should be resolved by getWebCryptoAlgoName flow analysis)
const encParams = { name: 'AES-GCM', iv: new Uint8Array(12) };
crypto.subtle.encrypt(encParams, key, data);

const signAlgo = 'HMAC';
crypto.subtle.sign(signAlgo, hmacKey, data);

// =============================================================================
// CryptoJS — patterns that should be caught
// =============================================================================
const CryptoJS = require('crypto-js');

// Direct calls
CryptoJS.SHA256('data');
CryptoJS.AES.encrypt('data', 'key');
CryptoJS.AES.encrypt('data', 'key', { mode: CryptoJS.mode.GCM });
CryptoJS.PBKDF2('pw', 'salt');

// Progressive
CryptoJS.algo.SHA256.create();
CryptoJS.algo.AES.createEncryptor(wordArrayKey);
CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, 'key');

// Random
CryptoJS.lib.WordArray.random(32);
