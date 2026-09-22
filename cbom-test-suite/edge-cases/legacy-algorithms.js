/**
 * CBOM Test Suite — Legacy / Insecure Algorithm Coverage
 * Exercises every old, broken, or deprecated algorithm to verify detection.
 *
 * ALL of these should be detected by the existing queries because:
 * - NodeCrypto.ql uses getArgValue() as a catch-all (no algorithm whitelist)
 * - CryptoJS.ql matches by receiver name (DES, TripleDES, RC4, etc.)
 * - node-forge query catches createCipher with any algorithm string
 */
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const forge = require('node-forge');

// =============================================================================
// BROKEN HASHES via node:crypto
// =============================================================================
crypto.createHash('md4').update('data').digest('hex');
crypto.createHash('md5').update('data').digest('hex');
crypto.createHash('sha1').update('data').digest('hex');
crypto.createHash('mdc2').update('data').digest('hex');
crypto.createHash('ripemd160').update('data').digest('hex');
crypto.createHash('whirlpool').update('data').digest('hex');

// =============================================================================
// DES — 56-bit key, brutable
// =============================================================================
crypto.createCipheriv('des-cbc', desKey8, iv8);
crypto.createCipheriv('des-ecb', desKey8, Buffer.alloc(0));
crypto.createCipheriv('des-cfb', desKey8, iv8);
crypto.createCipheriv('des-cfb1', desKey8, iv8);
crypto.createCipheriv('des-cfb8', desKey8, iv8);
crypto.createCipheriv('des-ofb', desKey8, iv8);

// DES decryption
crypto.createDecipheriv('des-cbc', desKey8, iv8);
crypto.createDecipheriv('des-ecb', desKey8, Buffer.alloc(0));

// Two-key 3DES (112-bit effective, meet-in-the-middle)
crypto.createCipheriv('des-ede', desKey16, Buffer.alloc(0));
crypto.createCipheriv('des-ede-cbc', desKey16, iv8);

// =============================================================================
// 3DES / Triple-DES — 64-bit block, Sweet32 after ~32GB
// =============================================================================
crypto.createCipheriv('des-ede3', desKey24, Buffer.alloc(0));
crypto.createCipheriv('des-ede3-cbc', desKey24, iv8);
crypto.createCipheriv('des-ede3-ecb', desKey24, Buffer.alloc(0));
crypto.createCipheriv('des-ede3-cfb', desKey24, iv8);
crypto.createCipheriv('des-ede3-cfb1', desKey24, iv8);
crypto.createCipheriv('des-ede3-cfb8', desKey24, iv8);
crypto.createCipheriv('des-ede3-ofb', desKey24, iv8);

// 3DES decryption
crypto.createDecipheriv('des-ede3-cbc', desKey24, iv8);
crypto.createDecipheriv('des-ede3-ecb', desKey24, Buffer.alloc(0));

// =============================================================================
// Blowfish — 64-bit block, Sweet32
// =============================================================================
crypto.createCipheriv('bf-cbc', bfKey, iv8);
crypto.createCipheriv('bf-ecb', bfKey, Buffer.alloc(0));
crypto.createCipheriv('bf-cfb', bfKey, iv8);
crypto.createCipheriv('bf-ofb', bfKey, iv8);
crypto.createDecipheriv('bf-cbc', bfKey, iv8);

// =============================================================================
// RC2 — variable key length, many weaknesses
// =============================================================================
crypto.createCipheriv('rc2-cbc', rc2Key, iv8);
crypto.createCipheriv('rc2-ecb', rc2Key, Buffer.alloc(0));
crypto.createCipheriv('rc2-cfb', rc2Key, iv8);
crypto.createCipheriv('rc2-ofb', rc2Key, iv8);
crypto.createCipheriv('rc2-40-cbc', rc2Key, iv8);  // Export-grade 40-bit
crypto.createCipheriv('rc2-64-cbc', rc2Key, iv8);  // 64-bit

// =============================================================================
// RC4 — stream cipher, multiple practical attacks
// =============================================================================
crypto.createCipheriv('rc4', rc4Key, Buffer.alloc(0));
crypto.createCipheriv('rc4-40', rc4Key, Buffer.alloc(0));  // Export-grade

// =============================================================================
// CAST5 — 64-bit block
// =============================================================================
crypto.createCipheriv('cast-cbc', castKey, iv8);
crypto.createCipheriv('cast5-cbc', castKey, iv8);
crypto.createCipheriv('cast5-ecb', castKey, Buffer.alloc(0));
crypto.createCipheriv('cast5-cfb', castKey, iv8);
crypto.createCipheriv('cast5-ofb', castKey, iv8);

// =============================================================================
// IDEA — patented (expired), 64-bit block
// =============================================================================
crypto.createCipheriv('idea-cbc', ideaKey, iv8);
crypto.createCipheriv('idea-ecb', ideaKey, Buffer.alloc(0));
crypto.createCipheriv('idea-cfb', ideaKey, iv8);
crypto.createCipheriv('idea-ofb', ideaKey, iv8);

// =============================================================================
// SEED — Korean standard, 128-bit block but limited adoption
// =============================================================================
crypto.createCipheriv('seed-cbc', seedKey, iv16);
crypto.createCipheriv('seed-ecb', seedKey, Buffer.alloc(0));
crypto.createCipheriv('seed-cfb', seedKey, iv16);
crypto.createCipheriv('seed-ofb', seedKey, iv16);

// =============================================================================
// DESX — DES with whitening, marginal improvement over DES
// =============================================================================
crypto.createCipheriv('desx-cbc', desxKey24, iv8);

// =============================================================================
// AES-ECB — no diffusion, pattern leakage
// =============================================================================
crypto.createCipheriv('aes-128-ecb', aes128Key, Buffer.alloc(0));
crypto.createCipheriv('aes-192-ecb', aes192Key, Buffer.alloc(0));
crypto.createCipheriv('aes-256-ecb', aes256Key, Buffer.alloc(0));

// =============================================================================
// AES-CBC (unauthenticated — padding oracle risk)
// =============================================================================
crypto.createCipheriv('aes-128-cbc', aes128Key, iv16);
crypto.createCipheriv('aes-192-cbc', aes192Key, iv16);
crypto.createCipheriv('aes-256-cbc', aes256Key, iv16);

// =============================================================================
// Deprecated createCipher API (password-based, EVP MD5 single iteration)
// =============================================================================
crypto.createCipher('des-cbc', 'password');
crypto.createCipher('des-ede3-cbc', 'password');
crypto.createCipher('bf-cbc', 'password');
crypto.createCipher('aes-256-cbc', 'password');
crypto.createCipher('rc2-cbc', 'password');
crypto.createCipher('rc4', 'password');
crypto.createCipher('cast-cbc', 'password');
crypto.createCipher('idea-cbc', 'password');

// Deprecated decryption
crypto.createDecipher('des-cbc', 'password');
crypto.createDecipher('aes-256-cbc', 'password');

// =============================================================================
// Weak HMAC digests
// =============================================================================
crypto.createHmac('md5', 'key').update('data').digest('hex');
crypto.createHmac('sha1', 'key').update('data').digest('hex');
crypto.createHmac('md4', 'key').update('data').digest('hex');
crypto.createHmac('ripemd160', 'key').update('data').digest('hex');

// =============================================================================
// Weak KDF digests
// =============================================================================
crypto.pbkdf2('pw', 'salt', 1000, 32, 'md5', () => {});     // MD5 digest
crypto.pbkdf2('pw', 'salt', 1000, 32, 'sha1', () => {});    // SHA-1 digest
crypto.pbkdf2Sync('pw', 'salt', 100, 32, 'md5');             // Low iterations + MD5
crypto.hkdf('md5', 'ikm', 'salt', 'info', 32, () => {});    // HKDF with MD5
crypto.hkdf('sha1', 'ikm', 'salt', 'info', 32, () => {});   // HKDF with SHA-1

// =============================================================================
// Weak signing digests
// =============================================================================
crypto.createSign('SHA1');
crypto.createSign('MD5');
crypto.createSign('DSA-SHA1');
crypto.createSign('RSA-MD5');
crypto.createSign('RSA-SHA1');
crypto.createVerify('SHA1');
crypto.createVerify('MD5');

// =============================================================================
// Weak key generation
// =============================================================================
crypto.generateKeyPairSync('dsa', { modulusLength: 1024 });  // DSA deprecated
crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });  // 1024-bit RSA too short

// =============================================================================
// Via variables (tests getArgValue resolution for old algos)
// =============================================================================
const legacyCipher = 'des-ede3-cbc';
crypto.createCipheriv(legacyCipher, desKey24, iv8);

const weakHash = 'md5';
crypto.createHash(weakHash).update('data').digest('hex');

const oldKdf = 'sha1';
crypto.pbkdf2('pw', 'salt', 1000, 32, oldKdf, () => {});

// Via ternary
const hashAlgo = useLegacy ? 'md5' : 'sha256';
crypto.createHash(hashAlgo).update('data').digest('hex');

// Via object map
const LEGACY_ALGOS = { cipher: 'des-ede3-cbc', hash: 'md5', hmac: 'sha1' };
crypto.createCipheriv(LEGACY_ALGOS.cipher, desKey24, iv8);
crypto.createHash(LEGACY_ALGOS.hash).update('data').digest('hex');

// Via array iteration
['md4', 'md5', 'sha1', 'ripemd160'].forEach(algo => {
  crypto.createHash(algo).update('data').digest('hex');
});

['des-cbc', 'des-ede3-cbc', 'bf-cbc', 'rc2-cbc', 'rc4'].forEach(cipher => {
  crypto.createCipheriv(cipher, key, iv);
});

// Via default parameter
function legacyHash(data, algo = 'md5') {
  return crypto.createHash(algo).update(data).digest('hex');
}

// Via call-site tracking
function legacyEncrypt(data, algo) {
  return crypto.createCipheriv(algo, key, iv);
}
legacyEncrypt('data', 'des-cbc');
legacyEncrypt('data', 'bf-cbc');
legacyEncrypt('data', 'rc4');

// Via compiled TS enum
var LegacyCipher;
(function (LegacyCipher) {
  LegacyCipher["DES"] = "des-cbc";
  LegacyCipher["TRIPLE_DES"] = "des-ede3-cbc";
  LegacyCipher["BLOWFISH"] = "bf-cbc";
  LegacyCipher["RC4"] = "rc4";
})(LegacyCipher || (LegacyCipher = {}));

crypto.createCipheriv(LegacyCipher.DES, desKey8, iv8);
crypto.createCipheriv(LegacyCipher.TRIPLE_DES, desKey24, iv8);

// =============================================================================
// CryptoJS legacy algorithms
// =============================================================================

// DES
CryptoJS.DES.encrypt('data', 'key');
CryptoJS.DES.decrypt(enc, 'key');
CryptoJS.DES.encrypt('data', 'key', { mode: CryptoJS.mode.ECB });
CryptoJS.DES.encrypt('data', 'key', { mode: CryptoJS.mode.CBC });

// TripleDES
CryptoJS.TripleDES.encrypt('data', 'key');
CryptoJS.TripleDES.decrypt(enc, 'key');
CryptoJS.TripleDES.encrypt('data', 'key', { mode: CryptoJS.mode.ECB });

// RC4
CryptoJS.RC4.encrypt('data', 'key');
CryptoJS.RC4.decrypt(enc, 'key');

// RC4Drop
CryptoJS.RC4Drop.encrypt('data', 'key');
CryptoJS.RC4Drop.decrypt(enc, 'key');

// Rabbit
CryptoJS.Rabbit.encrypt('data', 'key');
CryptoJS.Rabbit.decrypt(enc, 'key');

// Blowfish
CryptoJS.Blowfish.encrypt('data', 'key');
CryptoJS.Blowfish.decrypt(enc, 'key');
CryptoJS.Blowfish.encrypt('data', 'key', { mode: CryptoJS.mode.ECB });

// Weak hashes
CryptoJS.MD5('data');
CryptoJS.SHA1('data');
CryptoJS.HmacMD5('data', 'key');
CryptoJS.HmacSHA1('data', 'key');

// EvpKDF (MD5 with 1 iteration default)
CryptoJS.EvpKDF('password', 'salt');

// Progressive weak algos
CryptoJS.algo.MD5.create();
CryptoJS.algo.SHA1.create();
CryptoJS.algo.DES.createEncryptor(wKey);
CryptoJS.algo.TripleDES.createEncryptor(wKey);
CryptoJS.algo.RC4.createEncryptor(wKey);
CryptoJS.algo.RC4Drop.createEncryptor(wKey);
CryptoJS.algo.Rabbit.createEncryptor(wKey);
CryptoJS.algo.Blowfish.createEncryptor(wKey);

// =============================================================================
// node-forge legacy algorithms
// =============================================================================

// DES-CBC
forge.cipher.createCipher('DES-CBC', desKey);
forge.cipher.createDecipher('DES-CBC', desKey);

// DES-ECB
forge.cipher.createCipher('DES-ECB', desKey);

// 3DES-CBC
forge.cipher.createCipher('3DES-CBC', tripleDesKey);
forge.cipher.createDecipher('3DES-CBC', tripleDesKey);

// 3DES-ECB
forge.cipher.createCipher('3DES-ECB', tripleDesKey);

// AES-ECB (insecure mode)
forge.cipher.createCipher('AES-ECB', aesKey);

// Forge weak hashing
forge.md.md5.create().update('data').digest();
forge.md.sha1.create().update('data').digest();

// Forge HMAC with weak hash
const forgeHmac = forge.hmac.create();
forgeHmac.start('md5', 'key');
forgeHmac.update('data');

const forgeHmacSha1 = forge.hmac.create();
forgeHmacSha1.start('sha1', 'key');

// Forge PBKDF2 with weak hash (SHA-1 default)
forge.pkcs5.pbkdf2('password', 'salt', 1000, 32);

// Forge RSA with small key
forge.pki.rsa.generateKeyPair({ bits: 1024 });  // Too short
