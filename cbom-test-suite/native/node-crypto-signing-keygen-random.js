/**
 * CBOM Test Suite — node:crypto Signing, Asymmetric, KeyGen, DH, Random, Certs
 */
const crypto = require('crypto');

// =============================================================================
// Signing / Verification
// =============================================================================

// createSign / createVerify
const signSha256 = crypto.createSign('SHA256');
const signSha512 = crypto.createSign('SHA512');
const signSha1 = crypto.createSign('SHA1');
const signRsaPss = crypto.createSign('RSA-SHA256');

const verifySha256 = crypto.createVerify('SHA256');
const verifySha512 = crypto.createVerify('SHA512');
const verifySha1 = crypto.createVerify('SHA1');

// One-shot sign/verify (Node 12+)
const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const sig = crypto.sign('sha256', Buffer.from('data'), keyPair.privateKey);
const valid = crypto.verify('sha256', Buffer.from('data'), keyPair.publicKey, sig);

// Ed25519 one-shot (algorithm is null for EdDSA)
const edKey = crypto.generateKeyPairSync('ed25519');
const edSig = crypto.sign(null, Buffer.from('data'), edKey.privateKey);
const edValid = crypto.verify(null, Buffer.from('data'), edKey.publicKey, edSig);

// =============================================================================
// Asymmetric Encryption (RSA)
// =============================================================================
const rsaKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const encrypted = crypto.publicEncrypt(rsaKey.publicKey, Buffer.from('secret'));
const decrypted = crypto.privateDecrypt(rsaKey.privateKey, encrypted);

// Reverse direction (signing primitive)
const encPriv = crypto.privateEncrypt(rsaKey.privateKey, Buffer.from('data'));
const decPub = crypto.publicDecrypt(rsaKey.publicKey, encPriv);

// With explicit padding options
const encOaep = crypto.publicEncrypt(
  { key: rsaKey.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
  Buffer.from('secret')
);
const encPkcs1 = crypto.publicEncrypt(
  { key: rsaKey.publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  Buffer.from('secret')
);

// =============================================================================
// Key Generation
// =============================================================================

// generateKeyPair / generateKeyPairSync — all types
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
crypto.generateKeyPairSync('dsa', { modulusLength: 2048 });
crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
crypto.generateKeyPairSync('ed25519');
crypto.generateKeyPairSync('ed448');
crypto.generateKeyPairSync('x25519');
crypto.generateKeyPairSync('x448');
crypto.generateKeyPairSync('dh');

crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => {});
crypto.generateKeyPair('ed25519', (err, pub, priv) => {});

// generateKey / generateKeySync — symmetric
crypto.generateKeySync('aes', { length: 256 });
crypto.generateKeySync('aes', { length: 128 });
crypto.generateKeySync('hmac', { length: 256 });
crypto.generateKey('aes', { length: 256 }, (err, key) => {});

// Via variable
const keyType = 'ec';
crypto.generateKeyPairSync(keyType, { namedCurve: 'P-384' });

// Via array iteration
['ed25519', 'ed448', 'x25519', 'x448'].forEach(type => {
  crypto.generateKeyPairSync(type);
});

// =============================================================================
// Diffie-Hellman Key Exchange
// =============================================================================

// Classic DH
const dh = crypto.createDiffieHellman(2048);

// Named DH groups
const dhGroup1 = crypto.createDiffieHellmanGroup('modp14');
const dhGroup2 = crypto.getDiffieHellman('modp15');
const dhGroup3 = crypto.getDiffieHellman('modp16');

// ECDH
const ecdh1 = crypto.createECDH('secp256k1');
const ecdh2 = crypto.createECDH('prime256v1');
const ecdh3 = crypto.createECDH('secp384r1');
const ecdh4 = crypto.createECDH('secp521r1');

// Static diffieHellman
const dhPriv = crypto.createPrivateKey(/* ... */);
const dhPub = crypto.createPublicKey(/* ... */);
// crypto.diffieHellman({ privateKey: dhPriv, publicKey: dhPub });

// Via variable
const curveName = 'secp256k1';
crypto.createECDH(curveName);

// =============================================================================
// Key Import
// =============================================================================
const secretKey = crypto.createSecretKey(crypto.randomBytes(32));
const pubKey = crypto.createPublicKey(rsaKey.publicKey);
const privKey = crypto.createPrivateKey(rsaKey.privateKey);

// =============================================================================
// Random Number Generation
// =============================================================================
const randomBuf = crypto.randomBytes(32);
const randomBufCb = crypto.randomBytes(32, (err, buf) => {});
crypto.randomFill(Buffer.alloc(16), (err, buf) => {});
const randomFillBuf = crypto.randomFillSync(Buffer.alloc(16));
const randomNum = crypto.randomInt(100);
const randomNum2 = crypto.randomInt(10, 100);
crypto.randomInt(100, (err, n) => {});

// Web Crypto compat on node
const randomVals = crypto.getRandomValues(new Uint8Array(16));
const uuid = crypto.randomUUID();

// =============================================================================
// Certificates
// =============================================================================
// const cert = new crypto.X509Certificate(certBuffer);
const x509 = new crypto.X509Certificate(Buffer.from('dummy'));

// SPKAC certificate functions (legacy)
// crypto.Certificate.exportChallenge(spkac);
// crypto.Certificate.exportPublicKey(spkac);
// crypto.Certificate.verifySpkac(spkac);
