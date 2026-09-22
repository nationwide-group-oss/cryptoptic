/**
 * CBOM Test Suite — crypto-es
 * ES module rewrite of CryptoJS with identical API surface.
 * Your CryptoJS query may partially catch these (same method names).
 */
import { AES, DES, TripleDES, Rabbit, RC4, enc, mode, pad } from 'crypto-es';
import { MD5, SHA1, SHA256, SHA384, SHA512, SHA3, RIPEMD160 } from 'crypto-es';
import { HmacMD5, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512 } from 'crypto-es';
import { PBKDF2 } from 'crypto-es';
import { lib } from 'crypto-es';

// Hashing
const h1 = MD5('test');
const h2 = SHA1('test');
const h3 = SHA256('test');
const h4 = SHA384('test');
const h5 = SHA512('test');
const h6 = SHA3('test', { outputLength: 256 });
const h7 = RIPEMD160('test');

// HMAC
const hm1 = HmacMD5('msg', 'key');
const hm2 = HmacSHA1('msg', 'key');
const hm3 = HmacSHA256('msg', 'key');
const hm4 = HmacSHA384('msg', 'key');
const hm5 = HmacSHA512('msg', 'key');

// Ciphers
const enc1 = AES.encrypt('data', 'key');
const enc2 = DES.encrypt('data', 'key');
const enc3 = TripleDES.encrypt('data', 'key');
const enc4 = Rabbit.encrypt('data', 'key');
const enc5 = RC4.encrypt('data', 'key');

// AES with explicit mode
const enc6 = AES.encrypt('data', 'key', { mode: mode.ECB });

// KDF
const derived = PBKDF2('password', 'salt', { keySize: 8, iterations: 1000 });

// Random
const rand = lib.WordArray.random(32);
