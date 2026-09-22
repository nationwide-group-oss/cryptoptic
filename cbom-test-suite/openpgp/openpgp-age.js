/**
 * CBOM Test Suite — OpenPGP / Age
 * NOT COVERED by current queries.
 */

// =============================================================================
// openpgp (~300k/wk) — full OpenPGP implementation
// =============================================================================
const openpgp = require('openpgp');

// Key generation — RSA
const rsaKeyPair = await openpgp.generateKey({
  type: 'rsa',
  rsaBits: 4096,
  userIDs: [{ name: 'Test User', email: 'test@example.com' }],
  passphrase: 'super-secret',
});

// Key generation — ECC (default Curve25519)
const eccKeyPair = await openpgp.generateKey({
  type: 'ecc',
  curve: 'curve25519',
  userIDs: [{ name: 'ECC User', email: 'ecc@example.com' }],
  passphrase: 'password',
});

// Key generation — ECC with NIST curve
const p256KeyPair = await openpgp.generateKey({
  type: 'ecc',
  curve: 'p256',
  userIDs: [{ name: 'P256 User', email: 'p256@example.com' }],
});

// Key generation — ECC with Brainpool curve
const brainpoolKP = await openpgp.generateKey({
  type: 'ecc',
  curve: 'brainpoolP256r1',
  userIDs: [{ name: 'BP User', email: 'bp@example.com' }],
});

// Key generation — Ed25519 (v6)
const ed25519KP = await openpgp.generateKey({
  type: 'ecc',
  curve: 'ed25519',
  userIDs: [{ name: 'EdDSA User', email: 'ed@example.com' }],
});

// Encrypt message
const encrypted = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: 'Secret message' }),
  encryptionKeys: await openpgp.readKey({ armoredKey: publicKeyArmored }),
  signingKeys: await openpgp.decryptKey({
    privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
    passphrase: 'password',
  }),
});

// Encrypt with password (symmetric)
const symmetricEncrypted = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: 'Secret' }),
  passwords: ['passphrase'],
  config: { preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256 },
});

// Decrypt
const decrypted = await openpgp.decrypt({
  message: await openpgp.readMessage({ armoredMessage: encrypted }),
  decryptionKeys: await openpgp.decryptKey({
    privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
    passphrase: 'password',
  }),
  verificationKeys: await openpgp.readKey({ armoredKey: publicKeyArmored }),
});

// Sign (detached)
const signed = await openpgp.sign({
  message: await openpgp.createMessage({ text: 'Data to sign' }),
  signingKeys: privateKey,
  detached: true,
});

// Sign (cleartext)
const cleartextSigned = await openpgp.sign({
  message: await openpgp.createCleartextMessage({ text: 'Cleartext signed' }),
  signingKeys: privateKey,
});

// Verify
const verified = await openpgp.verify({
  message: await openpgp.readCleartextMessage({ cleartextMessage: cleartextSigned }),
  verificationKeys: publicKey,
});

// Streaming encryption
const encStream = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: readableStream }),
  encryptionKeys: publicKey,
  format: 'binary',
});

// Config options (algorithm preferences)
const encWithConfig = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: 'data' }),
  encryptionKeys: publicKey,
  config: {
    preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
    preferredHashAlgorithm: openpgp.enums.hash.sha512,
    preferredCompressionAlgorithm: openpgp.enums.compression.zlib,
    aeadProtect: true,
  },
});

// Key reading and manipulation
const publicKey2 = await openpgp.readKey({ armoredKey: armoredPub });
const privateKey2 = await openpgp.readPrivateKey({ armoredKey: armoredPriv });
const decryptedKey = await openpgp.decryptKey({ privateKey: privateKey2, passphrase: 'pw' });

// Reformat key (change algorithm preferences)
const reformattedKey = await openpgp.reformatKey({
  privateKey: decryptedKey,
  userIDs: [{ name: 'New Name', email: 'new@example.com' }],
});

// =============================================================================
// age-encryption (~20k/wk) — modern file encryption
// =============================================================================
const age = require('age-encryption');

// Generate X25519 identity (keypair)
const identity = await age.generateIdentity();
const recipient = await age.identityToRecipient(identity);

// Encrypt to recipient (X25519)
const ageEncrypted = await age.encrypt(Buffer.from('secret data'), [recipient]);

// Decrypt
const ageDecrypted = await age.decrypt(ageEncrypted, [identity]);

// Encrypt with passphrase (scrypt-based)
const passEncrypted = await age.encrypt(Buffer.from('secret data'), [], 'passphrase');

// Decrypt with passphrase
const passDecrypted = await age.decrypt(passEncrypted, [], 'passphrase');

// Multiple recipients
const id1 = await age.generateIdentity();
const id2 = await age.generateIdentity();
const r1 = await age.identityToRecipient(id1);
const r2 = await age.identityToRecipient(id2);
const multiEnc = await age.encrypt(Buffer.from('data'), [r1, r2]);
