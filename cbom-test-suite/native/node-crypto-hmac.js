/**
 * CBOM Test Suite — node:crypto HMAC
 * Tests createHmac with all digest algorithms
 */
const crypto = require('crypto');
const key = 'secret-key';

// All HMAC digest variants
const hmacMd5 = crypto.createHmac('md5', key).update('data').digest('hex');
const hmacSha1 = crypto.createHmac('sha1', key).update('data').digest('hex');
const hmacSha224 = crypto.createHmac('sha224', key).update('data').digest('hex');
const hmacSha256 = crypto.createHmac('sha256', key).update('data').digest('hex');
const hmacSha384 = crypto.createHmac('sha384', key).update('data').digest('hex');
const hmacSha512 = crypto.createHmac('sha512', key).update('data').digest('hex');
const hmacSha3 = crypto.createHmac('sha3-256', key).update('data').digest('hex');
const hmacBlake2b = crypto.createHmac('blake2b512', key).update('data').digest('hex');
const hmacRipemd = crypto.createHmac('ripemd160', key).update('data').digest('hex');

// Via variable
const hmacAlgo = 'sha256';
const hmacViaVar = crypto.createHmac(hmacAlgo, key).update('data').digest('hex');
