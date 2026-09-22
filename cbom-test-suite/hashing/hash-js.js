/**
 * CBOM Test Suite — hash.js
 * NOT COVERED. Extremely popular (~8M/wk), transitive dep of elliptic.
 * Chained API: hash.sha256().update(msg).digest('hex')
 */
const hash = require('hash.js');

// SHA family
const s1 = hash.sha1().update('data').digest('hex');
const s224 = hash.sha224().update('data').digest('hex');
const s256 = hash.sha256().update('data').digest('hex');
const s384 = hash.sha384().update('data').digest('hex');
const s512 = hash.sha512().update('data').digest('hex');

// RIPEMD-160
const r160 = hash.ripemd160().update('data').digest('hex');

// HMAC
const hm1 = hash.hmac(hash.sha256, 'key').update('data').digest('hex');
const hm2 = hash.hmac(hash.sha512, 'key').update('data').digest('hex');
const hm3 = hash.hmac(hash.sha1, 'key').update('data').digest('hex');

// Multiple updates (streaming)
const progressive = hash.sha256();
progressive.update('chunk1');
progressive.update('chunk2');
progressive.update('chunk3');
const result = progressive.digest('hex');

// Via variable
const algo = hash.sha256;
const h = algo().update('data').digest('hex');
