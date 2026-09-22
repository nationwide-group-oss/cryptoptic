/**
 * CBOM Test Suite — WebCrypto (SubtleCrypto) API
 * Tests every subtle.* method with all algorithm variants
 */

// =============================================================================
// subtle.digest — all algorithms
// =============================================================================

// String-form algorithm
crypto.subtle.digest('SHA-1', new Uint8Array([1, 2, 3]));
crypto.subtle.digest('SHA-256', new Uint8Array([1, 2, 3]));
crypto.subtle.digest('SHA-384', new Uint8Array([1, 2, 3]));
crypto.subtle.digest('SHA-512', new Uint8Array([1, 2, 3]));

// Object-form algorithm
crypto.subtle.digest({ name: 'SHA-256' }, new Uint8Array([1, 2, 3]));
crypto.subtle.digest({ name: 'SHA-512' }, new Uint8Array([1, 2, 3]));

// Via variable (string)
const digestAlgo = 'SHA-256';
crypto.subtle.digest(digestAlgo, new Uint8Array([1, 2, 3]));

// Via variable (object)
const digestParams = { name: 'SHA-384' };
crypto.subtle.digest(digestParams, new Uint8Array([1, 2, 3]));

// On standalone subtle reference
const subtle = crypto.subtle;
subtle.digest('SHA-256', new Uint8Array([1, 2, 3]));

// =============================================================================
// subtle.encrypt / subtle.decrypt
// =============================================================================

// AES-CBC
crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, aesKey, data);
crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, aesKey, data);

// AES-CTR
crypto.subtle.encrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 64 }, aesKey, data);
crypto.subtle.decrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 64 }, aesKey, data);

// AES-GCM
crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, aesKey, data);
crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, aesKey, data);

// RSA-OAEP
crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPubKey, data);
crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaPrivKey, data);

// String-form algorithm
crypto.subtle.encrypt('AES-GCM', aesKey, data);
crypto.subtle.decrypt('AES-GCM', aesKey, data);

// Via variable
const encAlgo = { name: 'AES-GCM', iv: new Uint8Array(12) };
crypto.subtle.encrypt(encAlgo, aesKey, data);

// Via standalone subtle reference
subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, aesKey, data);
subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, aesKey, data);

// =============================================================================
// subtle.sign / subtle.verify
// =============================================================================

// RSASSA-PKCS1-v1_5
crypto.subtle.sign('RSASSA-PKCS1-v1_5', rsaKey, data);
crypto.subtle.verify('RSASSA-PKCS1-v1_5', rsaKey, sig, data);

// RSA-PSS
crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, rsaKey, data);
crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, rsaKey, sig, data);

// ECDSA
crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, ecKey, data);
crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ecKey, sig, data);

// Ed25519 / Ed448
crypto.subtle.sign('Ed25519', ed25519Key, data);
crypto.subtle.verify('Ed25519', ed25519Key, sig, data);
crypto.subtle.sign('Ed448', ed448Key, data);
crypto.subtle.verify('Ed448', ed448Key, sig, data);

// HMAC
crypto.subtle.sign('HMAC', hmacKey, data);
crypto.subtle.verify('HMAC', hmacKey, sig, data);

// Object form
crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, ecKey, data);

// Via standalone subtle
subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, rsaKey, data);

// =============================================================================
// subtle.generateKey
// =============================================================================

// Symmetric
crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
crypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, ['encrypt', 'decrypt']);
crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
crypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey']);
crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign', 'verify']);

// Asymmetric — RSA
crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);

// Asymmetric — ECC
crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);

// Edwards curves
crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
crypto.subtle.generateKey({ name: 'Ed448' }, true, ['sign', 'verify']);
crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey']);
crypto.subtle.generateKey({ name: 'X448' }, true, ['deriveKey']);

// Via string form
crypto.subtle.generateKey('AES-GCM', true, ['encrypt']);

// Via variable
const keyGenAlgo = { name: 'AES-GCM', length: 256 };
crypto.subtle.generateKey(keyGenAlgo, true, ['encrypt', 'decrypt']);

// Via standalone subtle
subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);

// =============================================================================
// subtle.deriveKey / subtle.deriveBits
// =============================================================================

// ECDH
crypto.subtle.deriveKey({ name: 'ECDH', public: otherPubKey }, myPrivKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
crypto.subtle.deriveBits({ name: 'ECDH', public: otherPubKey }, myPrivKey, 256);

// HKDF
crypto.subtle.deriveKey({ name: 'HKDF', salt: salt, info: info, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
crypto.subtle.deriveBits({ name: 'HKDF', salt: salt, info: info, hash: 'SHA-256' }, baseKey, 256);

// PBKDF2
crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, baseKey, 256);

// X25519 / X448
crypto.subtle.deriveKey({ name: 'X25519', public: otherPubKey }, myPrivKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
crypto.subtle.deriveBits({ name: 'X25519', public: otherPubKey }, myPrivKey, 256);
crypto.subtle.deriveBits({ name: 'X448', public: otherPubKey }, myPrivKey, 448);

// =============================================================================
// subtle.importKey / subtle.exportKey
// =============================================================================

// Import with various algorithms
crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
crypto.subtle.importKey('pkcs8', keyData, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);
crypto.subtle.importKey('spki', keyData, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
crypto.subtle.importKey('jwk', jwkData, { name: 'Ed25519' }, true, ['sign']);
crypto.subtle.importKey('raw', keyData, { name: 'PBKDF2' }, false, ['deriveKey']);
crypto.subtle.importKey('raw', keyData, { name: 'HKDF' }, false, ['deriveKey']);

// Export
crypto.subtle.exportKey('raw', aesKey);
crypto.subtle.exportKey('pkcs8', rsaPrivKey);
crypto.subtle.exportKey('spki', rsaPubKey);
crypto.subtle.exportKey('jwk', ecKey);

// =============================================================================
// subtle.wrapKey / subtle.unwrapKey
// =============================================================================

// AES-KW wrapping
crypto.subtle.wrapKey('raw', targetKey, wrappingKey, { name: 'AES-KW' });
crypto.subtle.unwrapKey('raw', wrappedKey, wrappingKey, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);

// AES-GCM wrapping
crypto.subtle.wrapKey('raw', targetKey, wrappingKey, { name: 'AES-GCM', iv: iv });
crypto.subtle.unwrapKey('raw', wrappedKey, wrappingKey, { name: 'AES-GCM', iv: iv }, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);

// RSA-OAEP wrapping
crypto.subtle.wrapKey('raw', targetKey, rsaPubKey, { name: 'RSA-OAEP' });
crypto.subtle.unwrapKey('raw', wrappedKey, rsaPrivKey, { name: 'RSA-OAEP' }, { name: 'AES-CBC', length: 256 }, true, ['encrypt']);
