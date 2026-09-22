/**
 * CBOM Test Suite — node:crypto Hashing
 * Tests every hash algorithm variant for createHash and hash()
 */
const crypto = require('crypto');

// =============================================================================
// createHash — all algorithms
// =============================================================================

// MD family
const md4Hash = crypto.createHash('md4').update('test').digest('hex');
const md5Hash = crypto.createHash('md5').update('test').digest('hex');

// SHA-1 (both naming variants)
const sha1a = crypto.createHash('sha1').update('test').digest('hex');
const sha1b = crypto.createHash('sha-1').update('test').digest('hex');

// SHA-2 family (both naming variants)
const sha224a = crypto.createHash('sha224').update('test').digest('hex');
const sha224b = crypto.createHash('sha-224').update('test').digest('hex');
const sha256a = crypto.createHash('sha256').update('test').digest('hex');
const sha256b = crypto.createHash('sha-256').update('test').digest('hex');
const sha384a = crypto.createHash('sha384').update('test').digest('hex');
const sha384b = crypto.createHash('sha-384').update('test').digest('hex');
const sha512a = crypto.createHash('sha512').update('test').digest('hex');
const sha512b = crypto.createHash('sha-512').update('test').digest('hex');

// SHA-3 family
const sha3_256 = crypto.createHash('sha3-256').update('test').digest('hex');
const sha3_384 = crypto.createHash('sha3-384').update('test').digest('hex');
const sha3_512 = crypto.createHash('sha3-512').update('test').digest('hex');

// SHAKE
const shake128 = crypto.createHash('shake128').update('test').digest('hex');
const shake256 = crypto.createHash('shake256').update('test').digest('hex');

// BLAKE2
const blake2b = crypto.createHash('blake2b512').update('test').digest('hex');
const blake2s = crypto.createHash('blake2s256').update('test').digest('hex');

// RIPEMD
const ripemd = crypto.createHash('ripemd160').update('test').digest('hex');

// SM3 (Chinese national standard)
const sm3 = crypto.createHash('sm3').update('test').digest('hex');

// Catch-all: unusual/unknown algorithm string
const whirlpool = crypto.createHash('whirlpool').update('test').digest('hex');

// =============================================================================
// crypto.hash() — one-shot (Node 21.7+)
// =============================================================================

// Direct method call on crypto object
const oneShot256 = crypto.hash('sha256', 'test data');
const oneShotMd5 = crypto.hash('md5', 'test data');
const oneShotSha3 = crypto.hash('sha3-512', 'test data');

// =============================================================================
// createHash with variable assignment (local flow)
// =============================================================================
const algo = 'sha256';
const hashViaVar = crypto.createHash(algo).update('data').digest('hex');

const selectedHash = 'sha512';
const hashViaVar2 = crypto.createHash(selectedHash).update('data').digest('hex');
