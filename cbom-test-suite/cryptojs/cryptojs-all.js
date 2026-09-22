/**
 * CBOM Test Suite — CryptoJS (crypto-js)
 * Tests every function, hash, cipher, KDF, progressive mode
 */
const CryptoJS = require('crypto-js');

// =============================================================================
// Hash Functions — one-shot
// =============================================================================
const md5 = CryptoJS.MD5('message');
const sha1 = CryptoJS.SHA1('message');
const sha224 = CryptoJS.SHA224('message');
const sha256 = CryptoJS.SHA256('message');
const sha384 = CryptoJS.SHA384('message');
const sha512 = CryptoJS.SHA512('message');
const ripemd = CryptoJS.RIPEMD160('message');

// SHA3 with output lengths
const sha3Default = CryptoJS.SHA3('message');
const sha3_256 = CryptoJS.SHA3('message', { outputLength: 256 });
const sha3_384 = CryptoJS.SHA3('message', { outputLength: 384 });
const sha3_512 = CryptoJS.SHA3('message', { outputLength: 512 });

// =============================================================================
// HMAC Functions — one-shot
// =============================================================================
const hmacMd5 = CryptoJS.HmacMD5('message', 'key');
const hmacSha1 = CryptoJS.HmacSHA1('message', 'key');
const hmacSha224 = CryptoJS.HmacSHA224('message', 'key');
const hmacSha256 = CryptoJS.HmacSHA256('message', 'key');
const hmacSha384 = CryptoJS.HmacSHA384('message', 'key');
const hmacSha512 = CryptoJS.HmacSHA512('message', 'key');
const hmacSha3 = CryptoJS.HmacSHA3('message', 'key');
const hmacRipemd = CryptoJS.HmacRIPEMD160('message', 'key');

// =============================================================================
// Cipher Functions — encrypt / decrypt
// =============================================================================
const key = 'secret-key';
const msg = 'plaintext';

// AES — default mode (CBC)
const aesEnc = CryptoJS.AES.encrypt(msg, key);
const aesDec = CryptoJS.AES.decrypt(aesEnc, key);

// AES — explicit CBC mode
const aesCbc = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.CBC });

// AES — CTR mode
const aesCtr = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.CTR });

// AES — ECB mode
const aesEcb = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.ECB });

// AES — CFB mode
const aesCfb = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.CFB });

// AES — OFB mode
const aesOfb = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.OFB });

// DES
const desEnc = CryptoJS.DES.encrypt(msg, key);
const desDec = CryptoJS.DES.decrypt(desEnc, key);
const desCbc = CryptoJS.DES.encrypt(msg, key, { mode: CryptoJS.mode.CBC });
const desEcb = CryptoJS.DES.encrypt(msg, key, { mode: CryptoJS.mode.ECB });

// TripleDES (3DES)
const tdesEnc = CryptoJS.TripleDES.encrypt(msg, key);
const tdesDec = CryptoJS.TripleDES.decrypt(tdesEnc, key);
const tdesCbc = CryptoJS.TripleDES.encrypt(msg, key, { mode: CryptoJS.mode.CBC });

// Rabbit (stream cipher)
const rabbitEnc = CryptoJS.Rabbit.encrypt(msg, key);
const rabbitDec = CryptoJS.Rabbit.decrypt(rabbitEnc, key);

// RC4
const rc4Enc = CryptoJS.RC4.encrypt(msg, key);
const rc4Dec = CryptoJS.RC4.decrypt(rc4Enc, key);

// RC4Drop
const rc4DropEnc = CryptoJS.RC4Drop.encrypt(msg, key);
const rc4DropDec = CryptoJS.RC4Drop.decrypt(rc4DropEnc, key);

// Blowfish
const bfEnc = CryptoJS.Blowfish.encrypt(msg, key);
const bfDec = CryptoJS.Blowfish.decrypt(bfEnc, key);
const bfCbc = CryptoJS.Blowfish.encrypt(msg, key, { mode: CryptoJS.mode.CBC });
const bfEcb = CryptoJS.Blowfish.encrypt(msg, key, { mode: CryptoJS.mode.ECB });

// =============================================================================
// Key Derivation Functions
// =============================================================================

// PBKDF2 — default hasher (SHA-1)
const pbkdf2Default = CryptoJS.PBKDF2('password', 'salt', { keySize: 256 / 32, iterations: 10000 });

// PBKDF2 — explicit SHA-256 hasher
const pbkdf2Sha256 = CryptoJS.PBKDF2('password', 'salt', {
  keySize: 256 / 32,
  iterations: 10000,
  hasher: CryptoJS.algo.SHA256
});

// PBKDF2 — explicit SHA-512 hasher
const pbkdf2Sha512 = CryptoJS.PBKDF2('password', 'salt', {
  keySize: 512 / 32,
  iterations: 10000,
  hasher: CryptoJS.algo.SHA512
});

// EvpKDF — default hasher (MD5)
const evpDefault = CryptoJS.EvpKDF('password', 'salt', { keySize: 256 / 32, iterations: 1000 });

// EvpKDF — explicit SHA-256 hasher
const evpSha256 = CryptoJS.EvpKDF('password', 'salt', {
  keySize: 256 / 32,
  iterations: 1000,
  hasher: CryptoJS.algo.SHA256
});

// =============================================================================
// Progressive Hashing
// =============================================================================
const progMd5 = CryptoJS.algo.MD5.create();
progMd5.update('part1'); progMd5.update('part2'); progMd5.finalize();

const progSha1 = CryptoJS.algo.SHA1.create();
const progSha256 = CryptoJS.algo.SHA256.create();
const progSha384 = CryptoJS.algo.SHA384.create();
const progSha512 = CryptoJS.algo.SHA512.create();
const progSha3 = CryptoJS.algo.SHA3.create();
const progRipemd = CryptoJS.algo.RIPEMD160.create();
const progSha224 = CryptoJS.algo.SHA224.create();

// =============================================================================
// Progressive Cipher
// =============================================================================
const progAesEnc = CryptoJS.algo.AES.createEncryptor(wordArrayKey, { iv: wordArrayIv });
const progAesDec = CryptoJS.algo.AES.createDecryptor(wordArrayKey, { iv: wordArrayIv });
const progDes = CryptoJS.algo.DES.createEncryptor(wordArrayKey, { iv: wordArrayIv });
const progTdes = CryptoJS.algo.TripleDES.createEncryptor(wordArrayKey, { iv: wordArrayIv });
const progRabbit = CryptoJS.algo.Rabbit.createEncryptor(wordArrayKey);
const progRc4 = CryptoJS.algo.RC4.createEncryptor(wordArrayKey);
const progRc4Drop = CryptoJS.algo.RC4Drop.createEncryptor(wordArrayKey);
const progBf = CryptoJS.algo.Blowfish.createEncryptor(wordArrayKey, { iv: wordArrayIv });

// =============================================================================
// Progressive HMAC
// =============================================================================
const progHmacSha256 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, 'key');
progHmacSha256.update('part1'); progHmacSha256.finalize();

const progHmacMd5 = CryptoJS.algo.HMAC.create(CryptoJS.algo.MD5, 'key');
const progHmacSha1 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA1, 'key');
const progHmacSha384 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA384, 'key');
const progHmacSha512 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, 'key');
const progHmacSha3 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA3, 'key');
const progHmacRipemd = CryptoJS.algo.HMAC.create(CryptoJS.algo.RIPEMD160, 'key');
const progHmacSha224 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA224, 'key');

// Fallback: HMAC.create with unresolvable argument
const progHmacUnknown = CryptoJS.algo.HMAC.create(getHasher(), 'key');

// =============================================================================
// Random / CSPRNG
// =============================================================================
const random128 = CryptoJS.lib.WordArray.random(16);
const random256 = CryptoJS.lib.WordArray.random(32);
