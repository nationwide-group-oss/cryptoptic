/**
 * CBOM Test Suite — libsodium-wrappers / sodium-native
 * NOT COVERED. Critical gap. Production-grade libsodium bindings.
 */

// =============================================================================
// libsodium-wrappers (WASM-based)
// =============================================================================
const sodium = require('libsodium-wrappers');
await sodium.ready;

// --- Authenticated Secret-Key Encryption (xsalsa20-poly1305) ---
const sbKey = sodium.crypto_secretbox_keygen();
const sbNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const sbCipher = sodium.crypto_secretbox_easy(message, sbNonce, sbKey);
const sbPlain = sodium.crypto_secretbox_open_easy(sbCipher, sbNonce, sbKey);

// --- Authenticated Public-Key Encryption (x25519 + xsalsa20-poly1305) ---
const aliceKp = sodium.crypto_box_keypair();
const bobKp = sodium.crypto_box_keypair();
const boxNonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
const boxCipher = sodium.crypto_box_easy(message, boxNonce, bobKp.publicKey, aliceKp.privateKey);
const boxPlain = sodium.crypto_box_open_easy(boxCipher, boxNonce, aliceKp.publicKey, bobKp.privateKey);

// Sealed box (anonymous sender)
const sealedBox = sodium.crypto_box_seal(message, bobKp.publicKey);
const sealedOpen = sodium.crypto_box_seal_open(sealedBox, bobKp.publicKey, bobKp.privateKey);

// --- AEAD (ChaCha20-Poly1305, XChaCha20-Poly1305) ---
const aeadKey = sodium.crypto_aead_chacha20poly1305_keygen();
const aeadNonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
const aeadCipher = sodium.crypto_aead_chacha20poly1305_encrypt(message, aad, null, aeadNonce, aeadKey);
const aeadPlain = sodium.crypto_aead_chacha20poly1305_decrypt(null, aeadCipher, aad, aeadNonce, aeadKey);

// IETF variant
const ietfKey = sodium.crypto_aead_chacha20poly1305_ietf_keygen();
const ietfNonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
const ietfCipher = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(message, aad, null, ietfNonce, ietfKey);

// XChaCha20-Poly1305
const xchachaKey = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
const xchacha_nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
const xchacha_cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, aad, null, xchacha_nonce, xchachaKey);
const xchacha_plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, xchacha_cipher, aad, xchacha_nonce, xchachaKey);

// --- Signing (Ed25519) ---
const signKp = sodium.crypto_sign_keypair();
const signed = sodium.crypto_sign(message, signKp.privateKey);
const opened = sodium.crypto_sign_open(signed, signKp.publicKey);

// Detached signature
const detSig = sodium.crypto_sign_detached(message, signKp.privateKey);
const detValid = sodium.crypto_sign_verify_detached(detSig, message, signKp.publicKey);

// From seed
const signSeed = sodium.randombytes_buf(sodium.crypto_sign_SEEDBYTES);
const signFromSeed = sodium.crypto_sign_seed_keypair(signSeed);

// Ed25519 -> Curve25519 conversion
const curvePub = sodium.crypto_sign_ed25519_pk_to_curve25519(signKp.publicKey);
const curvePriv = sodium.crypto_sign_ed25519_sk_to_curve25519(signKp.privateKey);

// --- Hashing (SHA-512) ---
const hashResult = sodium.crypto_hash(message);
const hashSha512 = sodium.crypto_hash_sha512(message);
const hashSha256 = sodium.crypto_hash_sha256(message);

// --- Generic Hashing (BLAKE2b) ---
const ghash = sodium.crypto_generichash(32, message);
const ghashKeyed = sodium.crypto_generichash(32, message, key);

// Streaming BLAKE2b
const ghState = sodium.crypto_generichash_init(key, 32);
sodium.crypto_generichash_update(ghState, chunk1);
sodium.crypto_generichash_update(ghState, chunk2);
const ghFinal = sodium.crypto_generichash_final(ghState, 32);

// Short hash (SipHash-2-4)
const shortKey = sodium.crypto_shorthash_keygen();
const shortHash = sodium.crypto_shorthash(message, shortKey);

// --- Password Hashing (Argon2id/Argon2i) ---
const pwHash = sodium.crypto_pwhash(
  32,
  'password',
  salt,
  sodium.crypto_pwhash_OPSLIMIT_MODERATE,
  sodium.crypto_pwhash_MEMLIMIT_MODERATE,
  sodium.crypto_pwhash_ALG_ARGON2ID13
);

const pwHashStr = sodium.crypto_pwhash_str(
  'password',
  sodium.crypto_pwhash_OPSLIMIT_MODERATE,
  sodium.crypto_pwhash_MEMLIMIT_MODERATE
);
const pwValid = sodium.crypto_pwhash_str_verify(pwHashStr, 'password');

// Scrypt variant
const scryptHash = sodium.crypto_pwhash_scryptsalsa208sha256(
  32, 'password', salt,
  sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
  sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
);

// --- Key Derivation ---
const masterKey = sodium.crypto_kdf_keygen();
const subkey1 = sodium.crypto_kdf_derive_from_key(32, 1, 'context_', masterKey);
const subkey2 = sodium.crypto_kdf_derive_from_key(32, 2, 'context_', masterKey);

// --- Key Exchange ---
const kxClient = sodium.crypto_kx_keypair();
const kxServer = sodium.crypto_kx_keypair();
const clientSession = sodium.crypto_kx_client_session_keys(kxClient.publicKey, kxClient.privateKey, kxServer.publicKey);
const serverSession = sodium.crypto_kx_server_session_keys(kxServer.publicKey, kxServer.privateKey, kxClient.publicKey);

// --- Scalar Multiplication (Curve25519) ---
const scalarmult = sodium.crypto_scalarmult(privKey, pubKey);
const scalarmultBase = sodium.crypto_scalarmult_base(privKey);

// --- Random ---
const rand = sodium.randombytes_buf(32);
const randDet = sodium.randombytes_buf_deterministic(32, seed);
const randInt = sodium.randombytes_uniform(100);

// --- Stream cipher (XSalsa20) ---
const streamKey = sodium.crypto_stream_keygen();
const streamNonce = sodium.randombytes_buf(sodium.crypto_stream_NONCEBYTES);
const stream = sodium.crypto_stream(100, streamNonce, streamKey);
const streamXor = sodium.crypto_stream_xor(message, streamNonce, streamKey);

// --- Auth (HMAC-SHA-512-256) ---
const authKey = sodium.crypto_auth_keygen();
const authTag = sodium.crypto_auth(message, authKey);
const authValid = sodium.crypto_auth_verify(authTag, message, authKey);

// HMAC-SHA-256
const hmac256Key = sodium.crypto_auth_hmacsha256_keygen();
const hmac256Tag = sodium.crypto_auth_hmacsha256(message, hmac256Key);

// HMAC-SHA-512
const hmac512Key = sodium.crypto_auth_hmacsha512_keygen();
const hmac512Tag = sodium.crypto_auth_hmacsha512(message, hmac512Key);

// =============================================================================
// sodium-native (native C addon — same API surface, different bindings)
// =============================================================================
const sodiumNative = require('sodium-native');

const nativeBuf = Buffer.alloc(32);
sodiumNative.randombytes_buf(nativeBuf);
sodiumNative.crypto_generichash(outputBuf, inputBuf);
sodiumNative.crypto_secretbox_easy(cipherBuf, msgBuf, nonceBuf, keyBuf);
sodiumNative.crypto_sign_detached(sigBuf, msgBuf, skBuf);
sodiumNative.crypto_pwhash(outBuf, passBuf, saltBuf, opsLimit, memLimit, alg);
