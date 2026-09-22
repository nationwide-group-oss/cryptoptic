/**
 * CBOM Test Suite — TypeScript-Specific Patterns
 * TypeScript adds type-level indirection that may affect CodeQL resolution.
 */
import * as crypto from 'crypto';
import { createHash, createHmac, createCipheriv, randomBytes, generateKeyPairSync } from 'crypto';

// =============================================================================
// Type-narrowed algorithm literals (as const / satisfies)
// =============================================================================

// as const — preserves literal type, should still be a StringLiteral in the AST
const hashAlgo = 'sha256' as const;
crypto.createHash(hashAlgo).update('data').digest('hex');

// satisfies — TypeScript 4.9+ (compiles away, should leave StringLiteral)
const cipherAlgo = 'aes-256-gcm' satisfies string;
crypto.createCipheriv(cipherAlgo, key, iv);

// =============================================================================
// Union type constrained algorithms
// =============================================================================
type HashAlgorithm = 'sha256' | 'sha384' | 'sha512';

function typedHash(data: string, algo: HashAlgorithm): string {
  return crypto.createHash(algo).update(data).digest('hex');
}

// Direct call with literal — should resolve
typedHash('data', 'sha256');
typedHash('data', 'sha512');

// =============================================================================
// Interface/Type-driven config
// =============================================================================
interface CryptoConfig {
  hashAlgorithm: string;
  cipherAlgorithm: string;
  keySize: number;
}

const config: CryptoConfig = {
  hashAlgorithm: 'sha256',
  cipherAlgorithm: 'aes-256-gcm',
  keySize: 32,
};

// config.hashAlgorithm is NOT resolvable by getArgValue
crypto.createHash(config.hashAlgorithm).update('data').digest('hex');
crypto.createCipheriv(config.cipherAlgorithm, key, iv);

// =============================================================================
// Destructured imports (named imports)
// Callee name should match: createHash, createHmac, etc.
// =============================================================================
const hash1 = createHash('sha256').update('data').digest('hex');
const hmac1 = createHmac('sha256', 'key').update('data').digest('hex');
const cipher1 = createCipheriv('aes-256-cbc', key, iv);
const rand = randomBytes(32);
const kp = generateKeyPairSync('ed25519');

// =============================================================================
// Namespace import (import * as crypto)
// Method calls on crypto.* should work
// =============================================================================
const hash2 = crypto.createHash('sha256').update('data').digest('hex');
const hmac2 = crypto.createHmac('sha512', 'key').update('data').digest('hex');

// =============================================================================
// Generic wrapper functions
// =============================================================================
function hash<T extends string>(data: string, algo: T): string {
  return crypto.createHash(algo).update(data).digest('hex');
}

hash('data', 'sha256');
hash('data', 'md5');

// =============================================================================
// Enum as algorithm source (compiled TS enum)
// =============================================================================
enum CipherMode {
  AES_128_CBC = 'aes-128-cbc',
  AES_256_CBC = 'aes-256-cbc',
  AES_256_GCM = 'aes-256-gcm',
  CHACHA = 'chacha20-poly1305',
}

// TS enums compile to objects — these access patterns may or may not resolve
crypto.createCipheriv(CipherMode.AES_256_GCM, key, iv);
crypto.createCipheriv(CipherMode.AES_128_CBC, crypto.randomBytes(16), iv);

// =============================================================================
// Const enum (inlined at compile time — SHOULD be resolvable)
// =============================================================================
const enum InlinedHash {
  SHA256 = 'sha256',
  SHA512 = 'sha512',
}

// After TS compilation, this becomes: crypto.createHash('sha256')
crypto.createHash(InlinedHash.SHA256).update('data').digest('hex');

// =============================================================================
// WebCrypto with TypeScript generics
// =============================================================================
async function generateKey<T extends 'AES-GCM' | 'AES-CBC'>(algo: T): Promise<CryptoKey> {
  return await crypto.subtle.generateKey({ name: algo, length: 256 }, true, ['encrypt', 'decrypt']);
}

generateKey('AES-GCM');
generateKey('AES-CBC');

// =============================================================================
// Type assertion on algorithm
// =============================================================================
const userAlgo = getUserInput() as 'sha256' | 'sha512';
crypto.createHash(userAlgo).update('data').digest('hex');

// Non-null assertion
const maybeAlgo: string | undefined = getAlgo();
crypto.createHash(maybeAlgo!).update('data').digest('hex');

// =============================================================================
// Record/Map types
// =============================================================================
const ALGO_REGISTRY: Record<string, string> = {
  default: 'sha256',
  secure: 'sha512',
  legacy: 'sha1',
};

// NOT resolvable — dynamic property access on typed object
crypto.createHash(ALGO_REGISTRY['default']).update('data').digest('hex');
crypto.createHash(ALGO_REGISTRY.secure).update('data').digest('hex');

// =============================================================================
// Class with generic crypto method
// =============================================================================
class TypedCryptoService<H extends string = 'sha256'> {
  constructor(private hashAlgo: H = 'sha256' as H) {}

  hash(data: string): string {
    return crypto.createHash(this.hashAlgo).update(data).digest('hex');
  }
}

const service = new TypedCryptoService('sha512');
service.hash('data');
