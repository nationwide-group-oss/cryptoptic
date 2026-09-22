/**
 * CBOM Test Suite — Encryption-at-Rest / Envelope Encryption
 * NOT COVERED by current queries.
 */

// =============================================================================
// @aws-crypto/client-node (~500k/wk) — AWS Encryption SDK
// =============================================================================
const { KmsKeyringNode, buildClient, CommitmentPolicy } = require('@aws-crypto/client-node');

const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

// KMS keyring
const keyring = new KmsKeyringNode({
  generatorKeyId: 'arn:aws:kms:us-east-1:123456789:key/uuid-here',
  keyIds: ['arn:aws:kms:us-east-1:123456789:key/another-uuid'],
});

// Encrypt
const { result: encResult } = await encrypt(keyring, 'secret data', {
  encryptionContext: { purpose: 'test', department: 'engineering' },
});

// Decrypt
const { plaintext, messageHeader } = await decrypt(keyring, encResult);

// Streaming encryption
const { encryptStream, decryptStream } = require('@aws-crypto/client-node');
const encStream = encryptStream(keyring, { encryptionContext: { stage: 'demo' } });
const decStream = decryptStream(keyring);

// Raw AES keyring (for testing/local)
const { RawAesKeyringNode, RawAesWrappingSuiteIdentifier } = require('@aws-crypto/client-node');
const rawAesKeyring = new RawAesKeyringNode({
  keyName: 'local-aes-key',
  keyNamespace: 'local',
  wrappingSuite: RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING,
  unencryptedMasterKey: new Uint8Array(32),
});

// Raw RSA keyring
const { RawRsaKeyringNode } = require('@aws-crypto/client-node');
const rawRsaKeyring = new RawRsaKeyringNode({
  keyName: 'local-rsa-key',
  keyNamespace: 'local',
  rsaPublicKey: rsaPubPem,
  rsaPrivateKey: rsaPrivPem,
  oaepHash: 'sha256',
});

// =============================================================================
// aes-js (~1M/wk) — pure JavaScript AES
// =============================================================================
const aesjs = require('aes-js');

// AES-CTR
const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
const ctrEncrypted = aesCtr.encrypt(plaintext);
const aesCtrDec = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
const ctrDecrypted = aesCtrDec.decrypt(ctrEncrypted);

// AES-CBC
const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
const cbcEncrypted = aesCbc.encrypt(paddedPlaintext);
const aesCbcDec = new aesjs.ModeOfOperation.cbc(key, iv);
const cbcDecrypted = aesCbcDec.decrypt(cbcEncrypted);

// AES-CFB
const aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, 16);
const cfbEncrypted = aesCfb.encrypt(plaintext);

// AES-OFB
const aesOfb = new aesjs.ModeOfOperation.ofb(key, iv);
const ofbEncrypted = aesOfb.encrypt(plaintext);

// AES-ECB (insecure — but must detect)
const aesEcb = new aesjs.ModeOfOperation.ecb(key);
const ecbEncrypted = aesEcb.encrypt(plaintext);

// Padding utilities
const padded = aesjs.padding.pkcs7.pad(plaintext);
const unpadded = aesjs.padding.pkcs7.strip(padded);

// Key from hex
const keyHex = aesjs.utils.hex.toBytes('0123456789abcdef0123456789abcdef');
const ctr2 = new aesjs.ModeOfOperation.ctr(keyHex);
