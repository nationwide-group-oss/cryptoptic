/**
 * CBOM Test Suite — Standalone Hashing Libraries
 * NONE covered by current queries.
 */

// =============================================================================
// js-sha256 / js-sha512 / js-sha3
// =============================================================================
const { sha256, sha224 } = require('js-sha256');
const { sha512, sha384, sha512_256, sha512_224 } = require('js-sha512');
const { sha3_256, sha3_512, sha3_384, sha3_224, keccak256, keccak512 } = require('js-sha3');

const jsSha256 = sha256('data');
const jsSha224 = sha224('data');
const jsSha512 = sha512('data');
const jsSha384 = sha384('data');
const jsSha512_256 = sha512_256('data');
const jsKeccak = keccak256('data');
const jsSha3 = sha3_256('data');

// HMAC via js-sha256
const hmacHash = sha256.hmac('key', 'data');

// Streaming
const h = sha256.create();
h.update('chunk1');
h.update('chunk2');
const result = h.hex();

// Array buffer input
const ab = new ArrayBuffer(4);
sha256(ab);
sha512(ab);

// =============================================================================
// jsSHA — class-based API
// =============================================================================
const jsSHA = require('jssha');

// SHA-256
const sha256obj = new jsSHA('SHA-256', 'TEXT');
sha256obj.update('data');
const hash256 = sha256obj.getHash('HEX');

// SHA-512
const sha512obj = new jsSHA('SHA-512', 'TEXT');
sha512obj.update('data');
const hash512 = sha512obj.getHash('HEX');

// SHA-1
const sha1obj = new jsSHA('SHA-1', 'TEXT');
sha1obj.update('data');

// SHA-3
const sha3obj = new jsSHA('SHA3-256', 'TEXT');
sha3obj.update('data');

// SHAKE-128 / SHAKE-256
const shake128 = new jsSHA('SHAKE128', 'TEXT', { shakeLen: 256 });
shake128.update('data');

const shake256 = new jsSHA('SHAKE256', 'TEXT', { shakeLen: 512 });
shake256.update('data');

// KMAC-128 / KMAC-256
const kmac128 = new jsSHA('KMAC128', 'TEXT', { kmacKey: { value: 'key', format: 'TEXT' } });
kmac128.update('data');

// cSHAKE
const cshake = new jsSHA('CSHAKE128', 'TEXT', { customization: { value: 'custom', format: 'TEXT' } });
cshake.update('data');

// HMAC via jsSHA
const hmacObj = new jsSHA('SHA-256', 'TEXT', { hmacKey: { value: 'key', format: 'TEXT' } });
hmacObj.update('data');
const hmacResult = hmacObj.getHash('HEX');

// =============================================================================
// sha.js — browserify ecosystem
// =============================================================================
const shajs = require('sha.js');

const shjsSha256 = shajs('sha256').update('data').digest('hex');
const shjsSha1 = shajs('sha1').update('data').digest('hex');
const shjsSha224 = shajs('sha224').update('data').digest('hex');
const shjsSha384 = shajs('sha384').update('data').digest('hex');
const shjsSha512 = shajs('sha512').update('data').digest('hex');

// Constructor form
const shjsNew = new shajs.sha256().update('data').digest();

// =============================================================================
// md5 (npm)
// =============================================================================
const md5 = require('md5');

const md5Hash = md5('message');
const md5Buffer = md5(Buffer.from('message'));

// =============================================================================
// keccak (npm) — native addon, Ethereum ecosystem
// =============================================================================
const { Keccak } = require('keccak');

// Function form
const createKeccakHash = require('keccak');
const k256 = createKeccakHash('keccak256').update('data').digest('hex');
const k512 = createKeccakHash('keccak512').update('data').digest('hex');
const kSha3 = createKeccakHash('sha3-256').update('data').digest('hex');

// =============================================================================
// blake3 (npm) — Rust-backed WASM/native
// =============================================================================
const blake3 = require('blake3');

const b3hash = blake3.hash('data');
const b3hex = blake3.hash('data').toString('hex');

// Keyed hash
const b3keyed = blake3.keyedHash(key32, 'data');

// Key derivation
const b3derived = blake3.deriveKey('context string', 'input key material');

// Streaming
const b3hasher = blake3.createHash();
b3hasher.update('chunk1');
b3hasher.update('chunk2');
const b3result = b3hasher.digest();

// Keyed streaming
const b3keyedHasher = blake3.createKeyed(key32);
b3keyedHasher.update('data');

// =============================================================================
// Non-cryptographic hashes (optional tracking)
// =============================================================================

// xxhash-wasm
const xxhash = require('xxhash-wasm');
const { h32, h64 } = await xxhash();
const xx32 = h32('data');
const xx64 = h64('data');

// murmurhash-js
const murmurhash = require('murmurhash');
const mm2 = murmurhash.v2('data');
const mm3 = murmurhash.v3('data');
