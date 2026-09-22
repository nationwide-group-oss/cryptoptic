/**
 * CBOM Test Suite — Miscellaneous Crypto-Consuming Libraries
 * NOT COVERED by current queries.
 */

// =============================================================================
// uuid (~60M/wk) — CSPRNG-based UUID generation
// =============================================================================
const { v4: uuidv4, v1: uuidv1, v5: uuidv5, v3: uuidv3 } = require('uuid');

// v4 — random (CSPRNG: crypto.getRandomValues / crypto.randomBytes)
const id1 = uuidv4();
const id2 = uuidv4();

// v1 — timestamp + random
const id3 = uuidv1();

// v5 — SHA-1 namespace hash
const id4 = uuidv5('hello', uuidv5.DNS);
const id5 = uuidv5('hello', uuidv5.URL);

// v3 — MD5 namespace hash
const id6 = uuidv3('hello', uuidv3.DNS);

// Custom random source
const id7 = uuidv4({ random: customRandomBytes });
const id8 = uuidv4({ rng: () => crypto.randomBytes(16) });

// =============================================================================
// nanoid (~15M/wk) — CSPRNG-based ID generation
// =============================================================================
const { nanoid, customAlphabet } = require('nanoid');

const nid1 = nanoid();        // 21 chars, uses crypto.getRandomValues
const nid2 = nanoid(32);      // Custom length

// Custom alphabet (still CSPRNG)
const customId = customAlphabet('0123456789abcdef', 16);
const hexId = customId();

// Non-secure (Math.random — should be flagged differently)
const { nanoid: nanoidNonSecure } = require('nanoid/non-secure');
const insecureId = nanoidNonSecure();

// Async
const { nanoid: nanoidAsync } = require('nanoid/async');
const asyncId = await nanoidAsync();

// =============================================================================
// crypto-random-string (~1M/wk)
// =============================================================================
const cryptoRandomString = require('crypto-random-string');

const randomStr1 = cryptoRandomString({ length: 32, type: 'hex' });
const randomStr2 = cryptoRandomString({ length: 24, type: 'base64' });
const randomStr3 = cryptoRandomString({ length: 16, type: 'alphanumeric' });
const randomStr4 = cryptoRandomString({ length: 20, type: 'url-safe' });
const randomStr5 = cryptoRandomString({ length: 10, type: 'numeric' });
const randomStr6 = cryptoRandomString({ length: 12, characters: 'abc123' });

// Async
const asyncStr = await cryptoRandomString.async({ length: 32, type: 'hex' });

// =============================================================================
// cuid2 (~500k/wk) — collision-resistant ID (uses SHA3)
// =============================================================================
const { createId, init } = require('@paralleldrive/cuid2');
const cuid = createId();
const customCuid = init({ length: 32, fingerprint: 'my-app' });

// =============================================================================
// ulid (~300k/wk) — Universally Unique Lexicographically Sortable Identifier
// =============================================================================
const { ulid, monotonicFactory } = require('ulid');
const ulidId = ulid(); // Uses crypto.getRandomValues
const monotonic = monotonicFactory();
const mId = monotonic();

// =============================================================================
// secure-random (~50k/wk) — cross-platform CSPRNG
// =============================================================================
const secureRandom = require('secure-random');
const rand1 = secureRandom(32, { type: 'Buffer' });
const rand2 = secureRandom(16, { type: 'Uint8Array' });
const rand3 = secureRandom.randomBuffer(64);
const rand4 = secureRandom.randomUint8Array(32);

// =============================================================================
// randomatic (~4M/wk) — random string patterns
// =============================================================================
const randomize = require('randomatic');
const r1 = randomize('Aa0', 16); // random alphanumeric
const r2 = randomize('0', 8);    // random numeric
const r3 = randomize('?', 12, { chars: 'abc123!@#' });

// =============================================================================
// hat (~2M/wk) — random unique ID generator
// =============================================================================
const hat = require('hat');
const hatId = hat();
const hatCustom = hat(256, 16); // 256 bits, base 16

// =============================================================================
// keypair (~200k/wk) — RSA key pair generation
// =============================================================================
const keypair = require('keypair');
const keys = keypair({ bits: 2048 });
const strongKeys = keypair({ bits: 4096 });
// keys.public, keys.private
