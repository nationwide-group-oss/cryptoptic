/**
 * CBOM Test Suite — Edge Cases & Evasion Patterns
 * These test patterns that defeat the current query's heuristics.
 *
 * Each section is labeled with whether it SHOULD be found, and whether
 * the current queries WILL find it (expected result).
 */
const crypto = require('crypto');

// =============================================================================
// PATTERN 1: Wrapper Functions
// The createHash call IS visible, but tracing back to call sites is not.
// EXPECTED: createHash detected in this file, but callers of hashData() are invisible
// =============================================================================
function hashData(data, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(data).digest('hex');
}

// These call crypto indirectly — NOT detectable by current queries
const passwordHash = hashData('user-password', 'sha512');
const tokenHash = hashData('session-token');
const checksum = hashData(fileContents, 'md5'); // Weak hash used for checksums

// Re-exported wrapper
module.exports.secureHash = hashData;

// =============================================================================
// PATTERN 2: Class-Based Encapsulation
// EXPECTED: createCipheriv is visible, but this.algo is NOT resolvable → silent drop
// =============================================================================
class EncryptionService {
  constructor(algorithm = 'aes-256-gcm') {
    this.algo = algorithm;
    this.keyLength = algorithm.includes('128') ? 16 : 32;
  }

  encrypt(data, key, iv) {
    // This call EXISTS but algo is this.algo → unresolvable → NO RESULT
    const cipher = crypto.createCipheriv(this.algo, key, iv);
    cipher.update(data, 'utf8', 'hex');
    return cipher.final('hex');
  }

  decrypt(encrypted, key, iv) {
    const decipher = crypto.createDecipheriv(this.algo, key, iv);
    decipher.update(encrypted, 'hex', 'utf8');
    return decipher.final('utf8');
  }
}

// Instantiation with different algorithms
const defaultService = new EncryptionService();              // aes-256-gcm
const weakService = new EncryptionService('des-ede3-cbc');   // 3DES
const aes128Service = new EncryptionService('aes-128-cbc');  // AES-128

// =============================================================================
// PATTERN 3: Switch/Map-Based Algorithm Selection
// EXPECTED: createHash is visible but ALGO_MAP[level] is NOT resolvable → silent drop
// =============================================================================
const ALGO_MAP = {
  fast: 'md5',
  standard: 'sha256',
  secure: 'sha384',
  paranoid: 'sha512',
};

function flexibleHash(data, level = 'standard') {
  return crypto.createHash(ALGO_MAP[level]).update(data).digest('hex');
}

// Switch statement variant
function hashBySwitch(data, security) {
  let algo;
  switch (security) {
    case 'low': algo = 'md5'; break;
    case 'medium': algo = 'sha256'; break;
    case 'high': algo = 'sha512'; break;
    default: algo = 'sha256';
  }
  return crypto.createHash(algo).update(data).digest('hex');
}

// Ternary variant
function hashTernary(data, strong) {
  const algo = strong ? 'sha512' : 'sha256';
  return crypto.createHash(algo).update(data).digest('hex');
}

// =============================================================================
// PATTERN 4: Config-Driven Crypto
// EXPECTED: createCipheriv is visible but config.* is NOT resolvable → silent drop
// =============================================================================

// From JSON config file
const config = require('./config.json');
// config = { "cipher": "aes-256-gcm", "hash": "sha256", "keyDerivation": "scrypt" }

const configCipher = crypto.createCipheriv(config.cipher, key, iv);
const configHash = crypto.createHash(config.hash).update('data').digest();

// From environment variables
const envAlgo = process.env.HASH_ALGORITHM || 'sha256';
const envHash = crypto.createHash(envAlgo).update('data').digest('hex');

const envCipher = process.env.CIPHER_ALGO || 'aes-256-gcm';
const envCipherObj = crypto.createCipheriv(envCipher, key, iv);

// From command-line arguments
const cliAlgo = process.argv[2] || 'sha256';
const cliHash = crypto.createHash(cliAlgo).update('data').digest('hex');

// From database or remote config
async function getAlgoFromDb() {
  const row = await db.query('SELECT hash_algo FROM config WHERE id = 1');
  return crypto.createHash(row.hash_algo).update('data').digest('hex');
}

// =============================================================================
// PATTERN 5: Re-exported / Aliased Module Functions
// EXPECTED: callee name is NOT "createHash"/"createCipheriv" → NOT matched
// =============================================================================

// Destructured with rename
const { createHash: makeHash, createCipheriv: makeCipher } = require('crypto');
const aliasedHash = makeHash('sha256').update('data').digest('hex');
const aliasedCipher = makeCipher('aes-256-cbc', key, iv);

// Assigned to variable
const hashFn = crypto.createHash;
const cipherFn = crypto.createCipheriv;
const indirectHash = hashFn('sha256').update('data').digest('hex');
const indirectCipher = cipherFn('aes-256-cbc', key, iv);

// Via object spread
const cryptoFns = { ...crypto };
const spreadHash = cryptoFns.createHash('sha256').update('data').digest('hex');

// =============================================================================
// PATTERN 6: Dynamic Method Calls (Computed Property Access)
// EXPECTED: NO static callee name → completely invisible
// =============================================================================

// Dynamic method selection
const method = useGcm ? 'createCipheriv' : 'createCipher';
const dynamicCipher = crypto[method]('aes-256-cbc', key, iv);

// From array
const methods = ['createHash', 'createHmac'];
methods.forEach(m => {
  crypto[m]('sha256');
});

// Via variable
const fn = 'createHash';
crypto[fn]('sha256').update('data').digest('hex');

// =============================================================================
// PATTERN 7: Template Literal Algorithm Names
// EXPECTED: template literals are NOT StringLiteral → getArgValue returns nothing → silent drop
// =============================================================================

// Template literal with variable
const bits = 256;
const templateHash = crypto.createHash(`sha${bits}`).update('data').digest('hex');

// Template literal with expression
const version = 3;
const sha3Hash = crypto.createHash(`sha3-${version * 128}`).update('data').digest('hex');

// Template literal for cipher
const keySize = 256;
const mode = 'gcm';
const templateCipher = crypto.createCipheriv(`aes-${keySize}-${mode}`, key, iv);

// Tagged template (very unusual but possible)
function algo(strings, ...values) {
  return strings.reduce((acc, s, i) => acc + s + (values[i] || ''), '');
}
crypto.createHash(algo`sha${256}`).update('data').digest('hex');

// =============================================================================
// PATTERN 8: Factory / Builder Patterns
// EXPECTED: actual crypto call is INSIDE the factory — invisible at call site
// =============================================================================

class CryptoFactory {
  static create(options) {
    switch (options.type) {
      case 'hash':
        return crypto.createHash(options.algorithm);
      case 'cipher':
        return crypto.createCipheriv(options.algorithm, options.key, options.iv);
      case 'hmac':
        return crypto.createHmac(options.algorithm, options.key);
      default:
        throw new Error('Unknown type');
    }
  }
}

// Callers — the factory hides the actual crypto usage
const factoryHash = CryptoFactory.create({ type: 'hash', algorithm: 'sha256' });
const factoryCipher = CryptoFactory.create({ type: 'cipher', algorithm: 'aes-256-gcm', key, iv });
const factoryHmac = CryptoFactory.create({ type: 'hmac', algorithm: 'sha256', key: 'secret' });

// Builder pattern
class CipherBuilder {
  constructor() { this._algo = 'aes-256-cbc'; }
  algorithm(a) { this._algo = a; return this; }
  key(k) { this._key = k; return this; }
  iv(i) { this._iv = i; return this; }
  build() { return crypto.createCipheriv(this._algo, this._key, this._iv); }
}

const builtCipher = new CipherBuilder()
  .algorithm('aes-128-gcm')
  .key(key)
  .iv(iv)
  .build();

// =============================================================================
// PATTERN 9: Higher-Order Functions / Callbacks
// EXPECTED: createHash IS visible, but the algorithm comes from the callback parameter
// =============================================================================

function withHash(algo, fn) {
  const hash = crypto.createHash(algo);
  return fn(hash);
}

// The algorithm string is at the call site
withHash('sha256', (h) => h.update('data').digest('hex'));
withHash('md5', (h) => h.update('data').digest('hex'));

// Array of algorithms mapped through a function
const algos = ['sha256', 'sha512', 'sha3-256'];
const hashes = algos.map(a => crypto.createHash(a).update('data').digest('hex'));

// =============================================================================
// PATTERN 10: Proxy / Wrapper Objects
// EXPECTED: completely invisible — calls go through Proxy handler
// =============================================================================

const cryptoProxy = new Proxy(crypto, {
  get(target, prop) {
    if (prop === 'createHash') {
      return (algo) => {
        console.log(`Creating hash: ${algo}`);
        return target.createHash(algo);
      };
    }
    return target[prop];
  }
});

const proxyHash = cryptoProxy.createHash('sha256').update('data').digest('hex');

// =============================================================================
// PATTERN 11: Conditional Imports / Dynamic Requires
// EXPECTED: may or may not be resolved depending on CodeQL's analysis
// =============================================================================

// Dynamic require
const cryptoModule = require(isNode ? 'crypto' : 'crypto-browserify');
cryptoModule.createHash('sha256').update('data').digest('hex');

// Conditional import
let hashLib;
try {
  hashLib = require('@noble/hashes/sha256');
} catch {
  hashLib = { sha256: (d) => crypto.createHash('sha256').update(d).digest() };
}
hashLib.sha256('data');

// Lazy import
let _crypto;
function getCrypto() {
  if (!_crypto) _crypto = require('crypto');
  return _crypto;
}
getCrypto().createHash('sha256').update('data').digest('hex');

// =============================================================================
// PATTERN 12: String Concatenation for Algorithm Names
// EXPECTED: string concatenation is NOT a StringLiteral → silent drop
// =============================================================================

const prefix = 'aes';
const size = '256';
const cipherMode = 'gcm';
const concatAlgo = prefix + '-' + size + '-' + cipherMode;
const concatCipher = crypto.createCipheriv(concatAlgo, key, iv);

// Array join
const algoParts = ['aes', '256', 'cbc'];
const joinAlgo = algoParts.join('-');
const joinCipher = crypto.createCipheriv(joinAlgo, key, iv);

// =============================================================================
// PATTERN 13: Arguments Object / Rest Parameters
// EXPECTED: NOT resolvable by getArgValue
// =============================================================================

function createHashWrapper(...args) {
  return crypto.createHash(...args).update('data').digest('hex');
}
createHashWrapper('sha256');
createHashWrapper('md5');

function cryptoCall(method, ...args) {
  return crypto[method](...args);
}
cryptoCall('createHash', 'sha256');

// =============================================================================
// PATTERN 14: Promise Chain / Async Patterns
// EXPECTED: WebCrypto promises chain — algo in first call, crypto in .then()
// =============================================================================

// Chained WebCrypto
crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt'])
  .then(key => crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, key, data));

// Stored promise result
const keyPromise = crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
const cryptoKey = await keyPromise;
const encrypted2 = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey.publicKey, data);

// =============================================================================
// PATTERN 15: TypeScript Enum Patterns
// EXPECTED: enum values NOT resolvable as StringLiteral
// =============================================================================

// TypeScript enum (compiled to JS)
var HashAlgorithm;
(function (HashAlgorithm) {
  HashAlgorithm["SHA256"] = "sha256";
  HashAlgorithm["SHA512"] = "sha512";
  HashAlgorithm["MD5"] = "md5";
})(HashAlgorithm || (HashAlgorithm = {}));

const enumHash = crypto.createHash(HashAlgorithm.SHA256).update('data').digest('hex');
const enumHash2 = crypto.createHash(HashAlgorithm.MD5).update('data').digest('hex');

// const enum (inlined at compile time — SHOULD be visible as string literal)
// const hash = crypto.createHash("sha256").update('data').digest('hex');

// =============================================================================
// PATTERN 16: Module.exports / Re-export Patterns
// EXPECTED: crypto calls in the module are found, but the re-export creates
// an additional layer that hides the crypto usage from consumers
// =============================================================================

// Re-export as utility
module.exports = {
  hash: (data, algo = 'sha256') => crypto.createHash(algo).update(data).digest('hex'),
  encrypt: (data, key, iv, algo = 'aes-256-gcm') => {
    const cipher = crypto.createCipheriv(algo, key, iv);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
  },
  hmac: (data, key, algo = 'sha256') => crypto.createHmac(algo, key).update(data).digest('hex'),
  randomBytes: (n) => crypto.randomBytes(n),
};

// =============================================================================
// PATTERN 17: Decorator Pattern (common in NestJS / TypeORM)
// EXPECTED: createHash inside decorator handler — may or may not be found
// =============================================================================

function Hashed(algorithm = 'sha256') {
  return function (target, propertyKey, descriptor) {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args) {
      const result = originalMethod.apply(this, args);
      return crypto.createHash(algorithm).update(String(result)).digest('hex');
    };
    return descriptor;
  };
}

// =============================================================================
// PATTERN 18: Async Iterator / Generator Patterns
// EXPECTED: createHash inside generator — should be found but algo may not resolve
// =============================================================================

async function* hashStream(algorithm, chunks) {
  const hash = crypto.createHash(algorithm);
  for await (const chunk of chunks) {
    hash.update(chunk);
    yield chunk;
  }
  return hash.digest('hex');
}

// =============================================================================
// PATTERN 19: eval / Function constructor (extreme edge case)
// EXPECTED: completely invisible to static analysis
// =============================================================================

// eval-based crypto
eval("crypto.createHash('sha256').update('data').digest('hex')");

// Function constructor
const hashFn2 = new Function('crypto', 'data', "return crypto.createHash('sha256').update(data).digest('hex')");
hashFn2(crypto, 'test');

// =============================================================================
// PATTERN 20: WASM / Native Addon Crypto
// EXPECTED: completely invisible — crypto happens in compiled code
// =============================================================================

// WASM-based crypto (e.g. @aspect-build/rules_js uses wasm crypto internally)
const wasmCrypto = require('./crypto.wasm');
wasmCrypto.hash('data'); // AES/SHA inside WASM — invisible to CodeQL

// Native addon
const nativeAddon = require('./native-crypto.node');
nativeAddon.encrypt(key, data); // C++ crypto — invisible to CodeQL
