/**
 * CBOM Test Suite — Enhanced Resolution Test Cases
 * Tests the new resolution strategies added in v2.1:
 *   P5: Ternary / conditional
 *   P6: Object map value enumeration
 *   P7: Function default parameter values
 *   P8: Cross-function call-site argument tracking
 *   P9: TypeScript compiled enum member access
 *   Plus: Aliased function references and destructured renames
 */
const crypto = require('crypto');

// =============================================================================
// P5: Ternary / Conditional Expression
// EXPECTED: Reports BOTH 'sha512' and 'sha256'
// =============================================================================

// Direct ternary as argument
crypto.createHash(isStrong ? 'sha512' : 'sha256').update('data').digest('hex');

// Ternary assigned to variable, then passed
const hashAlgo = secure ? 'sha512' : 'sha256';
crypto.createHash(hashAlgo).update('data').digest('hex');

// Logical OR fallback (common with env vars)
const envAlgo = process.env.HASH_ALGORITHM || 'sha256';
crypto.createHash(envAlgo).update('data').digest('hex');

// Logical OR with cipher
const cipherAlgo = process.env.CIPHER || 'aes-256-gcm';
crypto.createCipheriv(cipherAlgo, key, iv);

// =============================================================================
// P6: Object Map Value Enumeration
// EXPECTED: Reports all values: 'md5', 'sha256', 'sha384', 'sha512'
// =============================================================================

// Dynamic index: MAP[variable]
const ALGO_MAP = { fast: 'md5', standard: 'sha256', secure: 'sha384', paranoid: 'sha512' };
crypto.createHash(ALGO_MAP[level]).update('data').digest('hex');

// Static property access: MAP.propertyName
crypto.createHash(ALGO_MAP.standard).update('data').digest('hex');

// Cipher map
const CIPHER_MAP = { legacy: 'des-ede3-cbc', standard: 'aes-256-cbc', modern: 'aes-256-gcm' };
crypto.createCipheriv(CIPHER_MAP[preference], key, iv);

// Via variable (intermediate assignment)
const selectedAlgo = ALGO_MAP[userChoice];
crypto.createHash(selectedAlgo).update('data').digest('hex');

// =============================================================================
// P7: Function Default Parameter Values
// EXPECTED: Reports default value 'sha256' for hashData, 'aes-256-gcm' for encrypt
// =============================================================================

function hashData(data, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(data).digest('hex');
}

function encrypt(data, algo = 'aes-256-gcm') {
  const cipher = crypto.createCipheriv(algo, key, iv);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

function hmacSign(data, hashAlgo = 'sha256', secretKey = 'default') {
  return crypto.createHmac(hashAlgo, secretKey).update(data).digest('hex');
}

// Arrow function with default
const quickHash = (data, algo = 'sha256') =>
  crypto.createHash(algo).update(data).digest('hex');

// =============================================================================
// P8: Cross-Function Call-Site Argument Tracking
// EXPECTED: Reports 'sha256', 'md5', 'sha512' from the call sites
// =============================================================================

function makeHash(data, algo) {
  return crypto.createHash(algo).update(data).digest('hex');
}

// Call sites with literal algorithm arguments
const h1 = makeHash('password', 'sha256');
const h2 = makeHash('checksum', 'md5');
const h3 = makeHash('signature', 'sha512');

// Cipher wrapper
function createEncryptor(algo, key, iv) {
  return crypto.createCipheriv(algo, key, iv);
}

const enc1 = createEncryptor('aes-256-gcm', key, iv);
const enc2 = createEncryptor('aes-128-cbc', key, iv);
const enc3 = createEncryptor('chacha20-poly1305', key, iv);

// HMAC wrapper
function computeHmac(data, algo) {
  return crypto.createHmac(algo, hmacKey).update(data).digest('hex');
}

computeHmac('data', 'sha256');
computeHmac('data', 'sha512');
computeHmac('data', 'md5');

// =============================================================================
// P9: TypeScript Compiled Enum / Object Constants
// EXPECTED: Reports 'sha256', 'sha512', 'md5' from enum values
// =============================================================================

// Compiled TypeScript enum (the pattern tsc produces)
var HashAlgorithm;
(function (HashAlgorithm) {
  HashAlgorithm["SHA256"] = "sha256";
  HashAlgorithm["SHA512"] = "sha512";
  HashAlgorithm["MD5"] = "md5";
})(HashAlgorithm || (HashAlgorithm = {}));

crypto.createHash(HashAlgorithm.SHA256).update('data').digest('hex');
crypto.createHash(HashAlgorithm.SHA512).update('data').digest('hex');
crypto.createHash(HashAlgorithm.MD5).update('data').digest('hex');

// Simple constant object (common in config)
const CipherMode = {
  AES_256_GCM: 'aes-256-gcm',
  AES_128_CBC: 'aes-128-cbc',
  CHACHA: 'chacha20-poly1305',
};

crypto.createCipheriv(CipherMode.AES_256_GCM, key, iv);
crypto.createCipheriv(CipherMode.AES_128_CBC, key, iv);
crypto.createCipheriv(CipherMode.CHACHA, key, iv);

// =============================================================================
// Aliased Function References
// EXPECTED: All should be detected as node:crypto calls with correct algorithm
// =============================================================================

// Aliased via assignment
const hashFn = crypto.createHash;
const aliasedHash = hashFn('sha256').update('data').digest('hex');

const cipherFn = crypto.createCipheriv;
const aliasedCipher = cipherFn('aes-256-cbc', key, iv);

// Destructured with rename
const { createHash: makeHash2, createCipheriv: makeCipher } = require('crypto');
const renamedHash = makeHash2('sha256').update('data').digest('hex');
const renamedCipher = makeCipher('aes-256-gcm', key, iv);

// =============================================================================
// Combined Patterns (multiple resolution strategies at once)
// =============================================================================

// Default param + call site tracking (P7 + P8)
function flexibleHash(data, algo = 'sha256') {
  return crypto.createHash(algo).update(data).digest('hex');
}
flexibleHash('data');               // → should resolve 'sha256' from default
flexibleHash('data', 'sha512');     // → should resolve 'sha512' from call site

// Object map + forEach (P6 + P3)
const algorithms = { hash: 'sha256', hmac: 'sha512' };
Object.values(algorithms).forEach(algo => {
  crypto.createHash(algo).update('data').digest('hex');
});

// Conditional + default (P5 + P7)
function conditionalHash(data, preferStrong = false) {
  const algo = preferStrong ? 'sha512' : 'sha256';
  return crypto.createHash(algo).update(data).digest('hex');
}
