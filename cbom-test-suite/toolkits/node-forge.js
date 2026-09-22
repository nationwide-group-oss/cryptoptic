/**
 * CBOM Test Suite — node-forge (~15M/wk)
 * NOT COVERED. Critical gap. Full crypto toolkit.
 */
const forge = require('node-forge');

// =============================================================================
// Hashing
// =============================================================================
const md5 = forge.md.md5.create().update('data').digest().toHex();
const sha1 = forge.md.sha1.create().update('data').digest().toHex();
const sha256 = forge.md.sha256.create().update('data').digest().toHex();
const sha384 = forge.md.sha384.create().update('data').digest().toHex();
const sha512 = forge.md.sha512.create().update('data').digest().toHex();

// Progressive hashing
const md = forge.md.sha256.create();
md.update('chunk1');
md.update('chunk2');
md.update('chunk3');
const hashResult = md.digest().toHex();

// =============================================================================
// HMAC
// =============================================================================
const hmac1 = forge.hmac.create();
hmac1.start('sha256', 'key');
hmac1.update('data');
const hmacResult = hmac1.digest().toHex();

const hmac2 = forge.hmac.create();
hmac2.start('sha1', 'key');
hmac2.update('data');

const hmac3 = forge.hmac.create();
hmac3.start('md5', 'key');
hmac3.update('data');

// =============================================================================
// Symmetric Ciphers
// =============================================================================

// AES-CBC
const cipherCbc = forge.cipher.createCipher('AES-CBC', key);
cipherCbc.start({ iv: iv });
cipherCbc.update(forge.util.createBuffer('data'));
cipherCbc.finish();

const decipherCbc = forge.cipher.createDecipher('AES-CBC', key);
decipherCbc.start({ iv: iv });

// AES-CTR
const cipherCtr = forge.cipher.createCipher('AES-CTR', key);
cipherCtr.start({ iv: iv });

// AES-GCM
const cipherGcm = forge.cipher.createCipher('AES-GCM', key);
cipherGcm.start({ iv: iv, additionalData: 'aad', tagLength: 128 });
cipherGcm.update(forge.util.createBuffer('data'));
cipherGcm.finish();
const tag = cipherGcm.mode.tag;

// AES-ECB
const cipherEcb = forge.cipher.createCipher('AES-ECB', key);

// AES-CFB
const cipherCfb = forge.cipher.createCipher('AES-CFB', key);

// AES-OFB
const cipherOfb = forge.cipher.createCipher('AES-OFB', key);

// DES / 3DES-CBC
const cipherDes = forge.cipher.createCipher('DES-CBC', desKey);
const cipher3Des = forge.cipher.createCipher('3DES-CBC', tripleDesKey);

// =============================================================================
// RSA
// =============================================================================

// Key generation
const rsaKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
const rsaKeyPair4096 = forge.pki.rsa.generateKeyPair({ bits: 4096 });

// Async key generation
forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {});

// Encryption — PKCS#1 v1.5
const encrypted = rsaKeyPair.publicKey.encrypt('secret');

// Encryption — OAEP
const encryptedOaep = rsaKeyPair.publicKey.encrypt('secret', 'RSA-OAEP');
const encryptedOaepSha256 = rsaKeyPair.publicKey.encrypt('secret', 'RSA-OAEP', {
  md: forge.md.sha256.create()
});

// Decryption
const decrypted = rsaKeyPair.privateKey.decrypt(encrypted);
const decryptedOaep = rsaKeyPair.privateKey.decrypt(encryptedOaep, 'RSA-OAEP');

// Signing
const mdSign = forge.md.sha256.create();
mdSign.update('data to sign');
const signature = rsaKeyPair.privateKey.sign(mdSign);

// Verification
const mdVerify = forge.md.sha256.create();
mdVerify.update('data to sign');
const isValid = rsaKeyPair.publicKey.verify(mdVerify.digest().bytes(), signature);

// PSS signing
const pss = forge.pss.create({
  md: forge.md.sha256.create(),
  mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
  saltLength: 32
});
const pssSig = rsaKeyPair.privateKey.sign(mdSign, pss);

// =============================================================================
// PBKDF2
// =============================================================================
const dk1 = forge.pkcs5.pbkdf2('password', 'salt', 10000, 32);
const dk2 = forge.pkcs5.pbkdf2('password', 'salt', 10000, 32, 'sha256');
const dk3 = forge.pkcs5.pbkdf2('password', 'salt', 10000, 32, forge.md.sha256.create());

// Async
forge.pkcs5.pbkdf2('password', 'salt', 10000, 32, 'sha256', (err, dk) => {});

// =============================================================================
// X.509 Certificates
// =============================================================================

// Create self-signed cert
const cert = forge.pki.createCertificate();
cert.publicKey = rsaKeyPair.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.sign(rsaKeyPair.privateKey, forge.md.sha256.create());

// PEM encoding/decoding
const pem = forge.pki.certificateToPem(cert);
const parsedCert = forge.pki.certificateFromPem(pem);

// CSR
const csr = forge.pki.createCertificationRequest();
csr.publicKey = rsaKeyPair.publicKey;
csr.sign(rsaKeyPair.privateKey);

// PKCS#12
const p12Asn1 = forge.pkcs12.toPkcs12Asn1(rsaKeyPair.privateKey, cert, 'password');
const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(p12Der), 'password');

// PKCS#7 / CMS
const p7 = forge.pkcs7.createEnvelopedData();
p7.addRecipient(cert);
p7.content = forge.util.createBuffer('secret data');
p7.encrypt();

// =============================================================================
// Random
// =============================================================================
const randomBytes = forge.random.getBytesSync(32);
forge.random.getBytes(32, (err, bytes) => {});

// =============================================================================
// TLS (forge's TLS implementation)
// =============================================================================
const tlsConn = forge.tls.createConnection({
  server: false,
  caStore: forge.pki.createCaStore([cert]),
  cipherSuites: [
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA
  ],
  verify: (connection, verified, depth, certs) => verified
});
