/**
 * CBOM Test Suite — create-hash / create-hmac (browserify polyfills)
 * PARTIALLY COVERED: callee names match node:crypto query but misattributed.
 * These are standalone npm packages, not node:crypto.
 */
const createHash = require('create-hash');
const createHmac = require('create-hmac');

// These will match createHash/createHmac in your node:crypto query
const h1 = createHash('sha256').update('data').digest('hex');
const h2 = createHash('sha1').update('data').digest('hex');
const h3 = createHash('md5').update('data').digest('hex');
const h4 = createHash('ripemd160').update('data').digest('hex');
const h5 = createHash('sha512').update('data').digest('hex');

const hm1 = createHmac('sha256', 'key').update('data').digest('hex');
const hm2 = createHmac('sha512', 'key').update('data').digest('hex');
