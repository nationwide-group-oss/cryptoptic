/**
 * CBOM Test Suite — sjcl (Stanford JS Crypto Library) & @noble/ciphers
 * NOT COVERED by current queries.
 */

// =============================================================================
// sjcl (~100k/wk)
// =============================================================================
const sjcl = require('sjcl');

// Convenient encrypt/decrypt (AES-CCM by default, PBKDF2 key derivation)
const enc = sjcl.encrypt('password', 'secret data');
const dec = sjcl.decrypt('password', enc);

// With explicit options
const enc2 = sjcl.encrypt('password', 'secret data', {
  mode: 'gcm',
  ks: 256,
  ts: 128,
  iter: 10000
});

// Hashing
const sha256 = sjcl.hash.sha256.hash('data');
const sha256hex = sjcl.codec.hex.fromBits(sha256);

const sha512 = sjcl.hash.sha512.hash('data');
const sha1 = sjcl.hash.sha1.hash('data');

// Progressive hashing
const hasher = new sjcl.hash.sha256();
hasher.update('chunk1');
hasher.update('chunk2');
const hashResult = hasher.finalize();

// HMAC
const hmac = new sjcl.misc.hmac(sjcl.codec.utf8String.toBits('key'));
const hmacResult = hmac.mac('data');

const hmac256 = new sjcl.misc.hmac(sjcl.codec.utf8String.toBits('key'), sjcl.hash.sha256);
const hmac512 = new sjcl.misc.hmac(sjcl.codec.utf8String.toBits('key'), sjcl.hash.sha512);

// PBKDF2
const dk = sjcl.misc.pbkdf2('password', 'salt', 10000, 256);
const dk2 = sjcl.misc.pbkdf2('password', 'salt', 10000, 256, sjcl.misc.hmac);

// Scrypt (if sjcl-scrypt plugin loaded)
// const scryptDk = sjcl.misc.scrypt('password', 'salt', 16384, 8, 1, 256);

// AES direct
const aesKey = sjcl.random.randomWords(8);
const aesCipher = new sjcl.cipher.aes(aesKey);
const aesEncrypted = aesCipher.encrypt([0, 1, 2, 3]);
const aesDecrypted = aesCipher.decrypt(aesEncrypted);

// AES-CCM
const ccmCipher = sjcl.mode.ccm.encrypt(new sjcl.cipher.aes(aesKey), plaintext, iv, aad, 64);
const ccmPlain = sjcl.mode.ccm.decrypt(new sjcl.cipher.aes(aesKey), ccmCipher, iv, aad, 64);

// AES-GCM
const gcmCipher = sjcl.mode.gcm.encrypt(new sjcl.cipher.aes(aesKey), plaintext, iv, aad, 128);
const gcmPlain = sjcl.mode.gcm.decrypt(new sjcl.cipher.aes(aesKey), gcmCipher, iv, aad, 128);

// AES-OCB2
const ocb2Cipher = sjcl.mode.ocb2.encrypt(new sjcl.cipher.aes(aesKey), plaintext, iv, aad, 64);

// ECC
const curve = sjcl.ecc.curves.c256; // P-256
const bnKey = sjcl.ecc.elGamal.generateKeys(curve);
const eccEnc = sjcl.ecc.elGamal.encrypt(bnKey.pub, 'data');
const eccDec = sjcl.ecc.elGamal.decrypt(bnKey.sec, eccEnc);

const ecdsaKeys = sjcl.ecc.ecdsa.generateKeys(curve);
const ecdsaSig = ecdsaKeys.sec.sign(sjcl.hash.sha256.hash('data'));
const ecdsaValid = ecdsaKeys.pub.verify(sjcl.hash.sha256.hash('data'), ecdsaSig);

// SRP
const srpGroup = sjcl.keyexchange.srp.knownGroup(2048);

// Random
const rand = sjcl.random.randomWords(8);

// =============================================================================
// @noble/ciphers (~800k/wk) — audited cipher library
// =============================================================================
import { aes_256_gcm, aes_128_gcm, aes_256_ctr, aes_128_cbc } from '@noble/ciphers/aes';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';
import { xsalsa20poly1305, salsa20 } from '@noble/ciphers/salsa';
import { aes_256_gcm_siv } from '@noble/ciphers/aes';
import { ff1 } from '@noble/ciphers/ff1';
import { managedNonce } from '@noble/ciphers/webcrypto';

// AES-GCM
const aesGcm = aes_256_gcm(key, nonce);
const encrypted = aesGcm.encrypt(plaintext);
const decrypted = aesGcm.decrypt(encrypted);

// AES-GCM-SIV (nonce-misuse resistant)
const siv = aes_256_gcm_siv(key, nonce);
const sivEnc = siv.encrypt(plaintext);

// AES-CTR
const aesCtr = aes_256_ctr(key, nonce);
const ctrEnc = aesCtr.encrypt(plaintext);

// AES-CBC
const aesCbc = aes_128_cbc(key, iv);
const cbcEnc = aesCbc.encrypt(plaintext);

// ChaCha20-Poly1305
const chacha = chacha20poly1305(key, nonce);
const chachaEnc = chacha.encrypt(plaintext);
const chachaDec = chacha.decrypt(chachaEnc);

// XChaCha20-Poly1305
const xchacha = xchacha20poly1305(key, nonce);
const xchachaEnc = xchacha.encrypt(plaintext);

// XSalsa20-Poly1305 (NaCl secretbox compatible)
const xsalsa = xsalsa20poly1305(key, nonce);
const xsalsaEnc = xsalsa.encrypt(plaintext);

// Salsa20
const salsa = salsa20(key, nonce);
const salsaEnc = salsa.encrypt(plaintext);

// FF1 (format-preserving encryption)
const ff1Cipher = ff1(16, key, tweak);
const ff1Enc = ff1Cipher.encrypt([1, 2, 3, 4, 5]);
const ff1Dec = ff1Cipher.decrypt(ff1Enc);

// Managed nonce (auto-prepend nonce)
const managed = managedNonce(aes_256_gcm)(key);
const managedEnc = managed.encrypt(plaintext);
const managedDec = managed.decrypt(managedEnc);
