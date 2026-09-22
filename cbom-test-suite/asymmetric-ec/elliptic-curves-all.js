/**
 * CBOM Test Suite — Asymmetric / Elliptic Curve Libraries
 * NONE covered by current queries. Critical gap.
 */

// =============================================================================
// elliptic (~10M/wk) — most popular JS EC library
// =============================================================================
const EC = require('elliptic').ec;
const EdDSA = require('elliptic').eddsa;

// secp256k1 (Bitcoin/Ethereum)
const secp256k1 = new EC('secp256k1');
const keypair = secp256k1.genKeyPair();
const pubKey = keypair.getPublic('hex');
const privKey = keypair.getPrivate('hex');
const sig = keypair.sign('message hash');
const valid = secp256k1.verify('message hash', sig, keypair);

// From existing key
const imported = secp256k1.keyFromPrivate('hex private key');
const importedPub = secp256k1.keyFromPublic('hex public key', 'hex');

// P-256 (prime256v1)
const p256 = new EC('p256');
const p256Key = p256.genKeyPair();
const p256Sig = p256Key.sign(Buffer.from('data'));
const p256Valid = p256.verify(Buffer.from('data'), p256Sig, p256Key);

// P-384
const p384 = new EC('p384');
const p384Key = p384.genKeyPair();

// P-521
const p521 = new EC('p521');
const p521Key = p521.genKeyPair();

// ECDH shared secret
const alice = secp256k1.genKeyPair();
const bob = secp256k1.genKeyPair();
const shared = alice.derive(bob.getPublic());

// EdDSA — Ed25519
const ed25519 = new EdDSA('ed25519');
const edKey = ed25519.keyFromSecret('secret seed');
const edSig = edKey.sign('message');
const edValid = ed25519.verify('message', edSig, edKey);

// =============================================================================
// @noble/curves (~4M/wk) — modern replacement for elliptic
// =============================================================================
import { secp256k1 as nobleSecp } from '@noble/curves/secp256k1';
import { ed25519 as nobleEd } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { p256 as nobleP256 } from '@noble/curves/p256';
import { p384 as nobleP384 } from '@noble/curves/p384';
import { p521 as nobleP521 } from '@noble/curves/p521';
import { x25519 } from '@noble/curves/ed25519';
import { bls12_381 } from '@noble/curves/bls12-381';

// secp256k1 ECDSA
const privKey2 = nobleSecp.utils.randomPrivateKey();
const pubKey2 = nobleSecp.getPublicKey(privKey2);
const sig2 = nobleSecp.sign('message hash', privKey2);
const valid2 = nobleSecp.verify(sig2, 'message hash', pubKey2);

// Shared secret (ECDH)
const sharedSecret = nobleSecp.getSharedSecret(privKeyA, pubKeyB);

// Ed25519
const edPriv = nobleEd.utils.randomPrivateKey();
const edPub = nobleEd.getPublicKey(edPriv);
const edSig2 = nobleEd.sign('message', edPriv);
const edValid2 = nobleEd.verify(edSig2, 'message', edPub);

// Ed448
const ed448Priv = ed448.utils.randomPrivateKey();
const ed448Pub = ed448.getPublicKey(ed448Priv);
const ed448Sig = ed448.sign('message', ed448Priv);

// X25519 key exchange
const x25519Priv = x25519.utils.randomPrivateKey();
const x25519Pub = x25519.getPublicKey(x25519Priv);
const x25519Shared = x25519.getSharedSecret(x25519Priv, otherPub);

// NIST curves
const p256Sig2 = nobleP256.sign('hash', p256Priv);
const p384Sig = nobleP384.sign('hash', p384Priv);
const p521Sig = nobleP521.sign('hash', p521Priv);

// BLS12-381 (pairing-based crypto)
const blsPriv = bls12_381.utils.randomPrivateKey();
const blsPub = bls12_381.getPublicKey(blsPriv);
const blsSig = bls12_381.sign('message', blsPriv);
const blsValid = bls12_381.verify(blsSig, 'message', blsPub);
// Aggregate signatures
const aggSig = bls12_381.aggregateSignatures([sig1, sig2, sig3]);

// ristretto255 / decaf448
import { ristretto255 } from '@noble/curves/ed25519';
import { decaf448 } from '@noble/curves/ed448';

const rPoint = ristretto255.hashToCurve('input');
const dPoint = decaf448.hashToCurve('input');

// =============================================================================
// @noble/secp256k1 (legacy, ~500k/wk)
// =============================================================================
import * as nobleLegacy from '@noble/secp256k1';

const legPriv = nobleLegacy.utils.randomPrivateKey();
const legPub = nobleLegacy.getPublicKey(legPriv);
const legSig = await nobleLegacy.sign('hash', legPriv);
const legValid = nobleLegacy.verify(legSig, 'hash', legPub);
const legShared = nobleLegacy.getSharedSecret(legPriv, otherPub);

// =============================================================================
// secp256k1 (native C++ binding, ~1M/wk)
// =============================================================================
const secp256k1Native = require('secp256k1');

const nativePriv = Buffer.from(randomBytes(32));
const nativePub = secp256k1Native.publicKeyCreate(nativePriv);
const nativeSig = secp256k1Native.ecdsaSign(msgHash, nativePriv);
const nativeValid = secp256k1Native.ecdsaVerify(nativeSig.signature, msgHash, nativePub);
const nativeRecov = secp256k1Native.ecdsaRecover(nativeSig.signature, nativeSig.recid, msgHash);
const nativeShared = secp256k1Native.ecdh(otherPub, nativePriv);

// =============================================================================
// tweetnacl (~10M/wk) — compact NaCl implementation
// =============================================================================
const nacl = require('tweetnacl');

// Box (authenticated public-key encryption: x25519 + xsalsa20-poly1305)
const aliceBox = nacl.box.keyPair();
const bobBox = nacl.box.keyPair();
const nonce = nacl.randomBytes(nacl.box.nonceLength);
const boxed = nacl.box(message, nonce, bobBox.publicKey, aliceBox.secretKey);
const opened = nacl.box.open(boxed, nonce, aliceBox.publicKey, bobBox.secretKey);

// Box — beforenm / afternm (precomputed shared key)
const shared2 = nacl.box.before(bobBox.publicKey, aliceBox.secretKey);
const boxedFast = nacl.box.after(message, nonce, shared2);

// SecretBox (authenticated secret-key encryption: xsalsa20-poly1305)
const secretKey2 = nacl.randomBytes(nacl.secretbox.keyLength);
const sbNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
const sealed = nacl.secretbox(message, sbNonce, secretKey2);
const unsealed = nacl.secretbox.open(sealed, sbNonce, secretKey2);

// Sign (Ed25519)
const signKeyPair = nacl.sign.keyPair();
const signed = nacl.sign(message, signKeyPair.secretKey);
const verified = nacl.sign.open(signed, signKeyPair.publicKey);
const detachedSig = nacl.sign.detached(message, signKeyPair.secretKey);
const detachedValid = nacl.sign.detached.verify(message, detachedSig, signKeyPair.publicKey);

// Hash (SHA-512)
const naclHash = nacl.hash(message);

// Random
const randomBuf = nacl.randomBytes(32);

// Key pair from seed
const seed = nacl.randomBytes(32);
const fromSeed = nacl.sign.keyPair.fromSeed(seed);
const fromSecret = nacl.sign.keyPair.fromSecretKey(existingSecret);

// =============================================================================
// eccrypto / eciesjs (~100k/wk)
// =============================================================================
const eccrypto = require('eccrypto');

// ECIES encrypt/decrypt
const eccPriv = eccrypto.generatePrivate();
const eccPub = eccrypto.getPublic(eccPriv);
const eccEncrypted = await eccrypto.encrypt(eccPub, Buffer.from('secret'));
const eccDecrypted = await eccrypto.decrypt(eccPriv, eccEncrypted);

// ECDSA sign/verify
const eccSig = await eccrypto.sign(eccPriv, msgHash);
const eccValid2 = await eccrypto.verify(eccPub, msgHash, eccSig);

// ECDH
const eccShared = await eccrypto.derive(eccPriv, otherPub);
