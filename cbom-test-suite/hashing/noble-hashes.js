/**
 * CBOM Test Suite — @noble/hashes
 * NOT COVERED by current queries. Major gap.
 * Function-call-based API with named imports.
 */
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { sha384 } from '@noble/hashes/sha512';
import { sha3_256, sha3_384, sha3_512, keccak_256 } from '@noble/hashes/sha3';
import { blake2b } from '@noble/hashes/blake2b';
import { blake2s } from '@noble/hashes/blake2s';
import { blake3 } from '@noble/hashes/blake3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2';
import { scrypt, scryptAsync } from '@noble/hashes/scrypt';
import { argon2id } from '@noble/hashes/argon2';

const data = new Uint8Array([1, 2, 3, 4]);

// Hash functions
const h1 = sha256(data);
const h2 = sha512(data);
const h3 = sha384(data);
const h4 = sha3_256(data);
const h5 = sha3_384(data);
const h6 = sha3_512(data);
const h7 = keccak_256(data);
const h8 = blake2b(data);
const h9 = blake2s(data);
const h10 = blake3(data);
const h11 = ripemd160(data);

// HMAC
const hm1 = hmac(sha256, 'key', data);
const hm2 = hmac(sha512, 'key', data);

// Key derivation
const hk1 = hkdf(sha256, 'ikm', 'salt', 'info', 32);
const pb1 = pbkdf2(sha256, 'password', 'salt', { c: 100000, dkLen: 32 });
const pb2 = await pbkdf2Async(sha256, 'password', 'salt', { c: 100000, dkLen: 32 });
const sc1 = scrypt('password', 'salt', { N: 2 ** 16, r: 8, p: 1, dkLen: 32 });
const sc2 = await scryptAsync('password', 'salt', { N: 2 ** 16, r: 8, p: 1, dkLen: 32 });
const ar1 = argon2id('password', 'salt', { t: 2, m: 65536, p: 1 });

// Blake2b with key and output length options
const h12 = blake2b(data, { key: new Uint8Array(32), dkLen: 64 });
const h13 = blake2s(data, { key: new Uint8Array(32), dkLen: 32 });
const h14 = blake3(data, { key: new Uint8Array(32) });

// Streaming/progressive API
const hasher = sha256.create();
hasher.update(data);
hasher.update(new Uint8Array([5, 6]));
const result = hasher.digest();
