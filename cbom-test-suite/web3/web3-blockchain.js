/**
 * CBOM Test Suite — Web3 / Blockchain Libraries
 * NOT COVERED by current queries.
 */

// =============================================================================
// ethers.js v6 (~3M/wk) — Ethereum library
// =============================================================================
const { ethers } = require('ethers');

// Hashing
const keccak = ethers.keccak256(ethers.toUtf8Bytes('data'));
const sha256Hash = ethers.sha256(ethers.toUtf8Bytes('data'));
const sha512Hash = ethers.sha512(ethers.toUtf8Bytes('data'));
const ripemd160Hash = ethers.ripemd160(ethers.toUtf8Bytes('data'));

// HMAC
const hmac = ethers.computeHmac('sha256', ethers.toUtf8Bytes('key'), ethers.toUtf8Bytes('data'));

// PBKDF2
const pbkdf2Key = ethers.pbkdf2(
  ethers.toUtf8Bytes('password'),
  ethers.toUtf8Bytes('salt'),
  100000,
  32,
  'sha256'
);

// Scrypt
const scryptKey = await ethers.scrypt(
  ethers.toUtf8Bytes('password'),
  ethers.toUtf8Bytes('salt'),
  16384, 8, 1, 32
);

// Wallet creation (secp256k1 key generation)
const wallet = ethers.Wallet.createRandom();
const wallet2 = new ethers.Wallet(privateKey);

// Signing (secp256k1 ECDSA)
const signedTx = await wallet.signTransaction(tx);
const signedMsg = await wallet.signMessage('Hello');

// SigningKey (raw secp256k1 operations)
const signingKey = new ethers.SigningKey(privateKey);
const pubKey = signingKey.publicKey;
const compressedPub = signingKey.compressedPublicKey;
const signature = signingKey.sign(digest);
const recovered = ethers.SigningKey.recoverPublicKey(digest, signature);
const sharedSecret = signingKey.computeSharedSecret(otherPublicKey);

// HD Wallet (BIP-32 key derivation + BIP-39 mnemonic)
const mnemonic = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16));
const hdNode = ethers.HDNodeWallet.fromMnemonic(mnemonic);
const child = hdNode.deriveChild(0);
const path = hdNode.derivePath("m/44'/60'/0'/0/0");

// Wallet encryption (AES-128-CTR + scrypt)
const encryptedJson = await wallet.encrypt('password');
const encryptedWithOpts = await wallet.encrypt('password', {
  scrypt: { N: 16384, r: 8, p: 1 }
});

// Wallet decryption
const decryptedWallet = await ethers.Wallet.fromEncryptedJson(encryptedJson, 'password');

// Random
const randomBuf = ethers.randomBytes(32);

// Address derivation (keccak256 of public key)
const address = ethers.computeAddress(publicKey);

// Message hashing (EIP-191)
const msgHash = ethers.hashMessage('Hello World');

// TypedData signing (EIP-712)
const typedSig = await wallet.signTypedData(domain, types, value);

// AbiCoder (not crypto per se, but uses keccak internally)
const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'address'], [123, addr]);
const funcSig = ethers.id('transfer(address,uint256)'); // keccak256 of function signature

// Solidity packed hashing
const solidityHash = ethers.solidityPackedKeccak256(['address', 'uint256'], [addr, amount]);
const soliditySha256 = ethers.solidityPackedSha256(['address', 'uint256'], [addr, amount]);

// =============================================================================
// ethers.js v5 (legacy but still in use)
// =============================================================================
const ethersV5 = require('ethers');

// v5 syntax differences
const keccakV5 = ethersV5.utils.keccak256(ethersV5.utils.toUtf8Bytes('data'));
const sha256V5 = ethersV5.utils.sha256(ethersV5.utils.toUtf8Bytes('data'));
const hmacV5 = ethersV5.utils.computeHmac('sha256', keyBytes, dataBytes);
const pbkdf2V5 = ethersV5.utils.pbkdf2(passwordBytes, saltBytes, 100000, 32, 'sha256');
const walletV5 = ethersV5.Wallet.createRandom();
const sigV5 = walletV5.signMessage('data');
const randomV5 = ethersV5.utils.randomBytes(32);
const hdV5 = ethersV5.utils.HDNode.fromMnemonic(mnemonic);

// =============================================================================
// web3.js (~1M/wk)
// =============================================================================
const Web3 = require('web3');
const web3 = new Web3();

// Hashing (keccak256 / sha3)
const web3Keccak = web3.utils.keccak256('data');
const web3Sha3 = web3.utils.sha3('data');
const web3SoliditySha3 = web3.utils.soliditySha3({ type: 'uint256', value: 123 });

// Account operations (secp256k1)
const account = web3.eth.accounts.create();
const account2 = web3.eth.accounts.create(web3.utils.randomHex(32));

// Sign
const signedData = web3.eth.accounts.sign('data', privateKey);
const signedTx2 = await web3.eth.accounts.signTransaction(txObj, privateKey);

// Recover
const recoveredAddr = web3.eth.accounts.recover('data', signature);

// Encrypt (keystore v3 — AES-128-CTR + scrypt/pbkdf2)
const keystore = web3.eth.accounts.encrypt(privateKey, 'password');
const decryptedAccount = web3.eth.accounts.decrypt(keystore, 'password');

// Wallet
const web3Wallet = web3.eth.accounts.wallet.create(5); // 5 random accounts
web3.eth.accounts.wallet.encrypt('password');

// Hash message (EIP-191)
const hashMsg = web3.eth.accounts.hashMessage('data');

// Random
const randomHex = web3.utils.randomHex(32);

// =============================================================================
// bitcoinjs-lib (~200k/wk)
// =============================================================================
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1'); // required peer dep

// Key pair (secp256k1)
const ECPair = require('ecpair').ECPairFactory(ecc);
const keyPair = ECPair.makeRandom();
const keyFromWIF = ECPair.fromWIF('5Kd3...');
const keyFromPriv = ECPair.fromPrivateKey(Buffer.from(privKeyHex, 'hex'));

// Address generation (involves SHA-256 + RIPEMD-160 = hash160)
const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey });
const { address: segwitAddr } = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey });
const { address: taprootAddr } = bitcoin.payments.p2tr({ internalPubkey: xOnlyPubkey });

// Transaction signing (secp256k1 ECDSA)
const psbt = new bitcoin.Psbt();
psbt.addInput({ hash: txid, index: 0, witnessUtxo: { script, value: 10000 } });
psbt.addOutput({ address: 'bc1q...', value: 9000 });
psbt.signInput(0, keyPair);
psbt.finalizeAllInputs();
const rawTx = psbt.extractTransaction().toHex();

// Taproot (Schnorr signatures)
const taprootPsbt = new bitcoin.Psbt();
taprootPsbt.addInput({
  hash: txid, index: 0,
  witnessUtxo: { script: taprootScript, value: 10000 },
  tapInternalKey: xOnlyPubkey,
});
taprootPsbt.signInput(0, tweakedSigner); // Schnorr/BIP340 signing

// BIP32 HD key derivation
const bip32 = require('bip32').BIP32Factory(ecc);
const seed = Buffer.from('...', 'hex');
const root = bip32.fromSeed(seed);
const child = root.derivePath("m/44'/0'/0'/0/0");
const childKey = child.privateKey;

// BIP39 mnemonic
const bip39 = require('bip39');
const mnemonic = bip39.generateMnemonic();
const bip39Seed = await bip39.mnemonicToSeed(mnemonic, 'optional passphrase');

// =============================================================================
// tiny-secp256k1 — peer dep for bitcoinjs
// =============================================================================
const tinySecp = require('tiny-secp256k1');

const isPriv = tinySecp.isPrivate(privKeyBuf);
const pub = tinySecp.pointFromScalar(privKeyBuf);
const sig = tinySecp.sign(msgHash, privKeyBuf);
const valid = tinySecp.verify(msgHash, pub, sig);
const schnorrSig = tinySecp.signSchnorr(msgHash, privKeyBuf);
const schnorrValid = tinySecp.verifySchnorr(msgHash, pub, schnorrSig);
const sharedPoint = tinySecp.pointMultiply(pub, scalar);
