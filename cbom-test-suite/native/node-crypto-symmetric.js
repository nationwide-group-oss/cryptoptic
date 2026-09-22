/**
 * CBOM Test Suite — node:crypto Symmetric Encryption
 * Tests createCipheriv, createDecipheriv, createCipher (deprecated), createDecipher (deprecated)
 */
const crypto = require('crypto');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// =============================================================================
// createCipheriv / createDecipheriv — all common algorithms
// =============================================================================

// AES modes
const aesCbc = crypto.createCipheriv('aes-256-cbc', key, iv);
const aesCtr = crypto.createCipheriv('aes-256-ctr', key, iv);
const aesGcm = crypto.createCipheriv('aes-256-gcm', key, iv);
const aesEcb = crypto.createCipheriv('aes-256-ecb', key, Buffer.alloc(0));
const aesCcm = crypto.createCipheriv('aes-256-ccm', key, crypto.randomBytes(12), { authTagLength: 16 });
const aesOfb = crypto.createCipheriv('aes-256-ofb', key, iv);
const aesCfb = crypto.createCipheriv('aes-256-cfb', key, iv);

// AES key sizes
const aes128 = crypto.createCipheriv('aes-128-cbc', crypto.randomBytes(16), iv);
const aes192 = crypto.createCipheriv('aes-192-cbc', crypto.randomBytes(24), iv);

// DES / 3DES
const desCbc = crypto.createCipheriv('des-cbc', crypto.randomBytes(8), crypto.randomBytes(8));
const desEde3 = crypto.createCipheriv('des-ede3-cbc', crypto.randomBytes(24), crypto.randomBytes(8));

// ChaCha20-Poly1305
const chacha = crypto.createCipheriv('chacha20-poly1305', key, crypto.randomBytes(12), { authTagLength: 16 });

// Camellia
const camellia = crypto.createCipheriv('camellia-256-cbc', key, iv);

// SM4 (Chinese national standard)
const sm4 = crypto.createCipheriv('sm4-cbc', crypto.randomBytes(16), iv);

// Decryption counterparts
const decAesGcm = crypto.createDecipheriv('aes-256-gcm', key, iv);
const decAesCbc = crypto.createDecipheriv('aes-256-cbc', key, iv);
const decChacha = crypto.createDecipheriv('chacha20-poly1305', key, crypto.randomBytes(12), { authTagLength: 16 });

// =============================================================================
// createCipher / createDecipher — deprecated but still in use
// =============================================================================
const deprecatedCipher = crypto.createCipher('aes-256-cbc', 'password');
const deprecatedDecipher = crypto.createDecipher('aes-256-cbc', 'password');
const deprecatedDes = crypto.createCipher('des-ede3-cbc', 'password');

// =============================================================================
// Via variable
// =============================================================================
const cipherAlgo = 'aes-256-gcm';
const cipherViaVar = crypto.createCipheriv(cipherAlgo, key, iv);

// Via variable assigned conditionally (should still resolve the literal)
let chosenAlgo = 'aes-128-cbc';
const cipherConditional = crypto.createCipheriv(chosenAlgo, crypto.randomBytes(16), iv);
