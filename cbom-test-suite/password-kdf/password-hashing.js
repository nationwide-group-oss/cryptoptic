/**
 * CBOM Test Suite — Password Hashing / KDF Libraries
 * NONE covered by current queries. Critical gap.
 */

// =============================================================================
// bcrypt (native C++ addon)
// =============================================================================
const bcrypt = require('bcrypt');

// Async
const saltRounds = 12;
const salt = await bcrypt.genSalt(saltRounds);
const bcryptHash = await bcrypt.hash('password123', salt);
const bcryptValid = await bcrypt.compare('password123', bcryptHash);

// One-shot with auto salt
const bcryptHash2 = await bcrypt.hash('password123', 10);

// Sync
const saltSync = bcrypt.genSaltSync(10);
const hashSync = bcrypt.hashSync('password123', saltSync);
const validSync = bcrypt.compareSync('password123', hashSync);

// =============================================================================
// bcryptjs (pure JS implementation)
// =============================================================================
const bcryptjs = require('bcryptjs');

// Async
const bjsSalt = await bcryptjs.genSalt(12);
const bjsHash = await bcryptjs.hash('password', bjsSalt);
const bjsValid = await bcryptjs.compare('password', bjsHash);

// Sync
const bjsSaltSync = bcryptjs.genSaltSync(10);
const bjsHashSync = bcryptjs.hashSync('password', bjsSaltSync);
const bjsValidSync = bcryptjs.compareSync('password', bjsHashSync);

// =============================================================================
// argon2 (native addon — PHC winner)
// =============================================================================
const argon2 = require('argon2');

// argon2id (recommended)
const argon2Hash = await argon2.hash('password', {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4
});
const argon2Valid = await argon2.verify(argon2Hash, 'password');

// argon2i
const argon2iHash = await argon2.hash('password', { type: argon2.argon2i });

// argon2d
const argon2dHash = await argon2.hash('password', { type: argon2.argon2d });

// With raw output
const rawHash = await argon2.hash('password', { raw: true });

// =============================================================================
// scrypt-js (pure JS scrypt — used by ethers.js)
// =============================================================================
const scrypt = require('scrypt-js');

// Callback-based
const key = await scrypt.scrypt(
  Buffer.from('password'),
  Buffer.from('salt'),
  16384,  // N
  8,      // r
  1,      // p
  32      // dkLen
);

// With progress callback
const key2 = await scrypt.scrypt(
  Buffer.from('password'),
  Buffer.from('salt'),
  16384, 8, 1, 64,
  (progress) => console.log(Math.round(progress * 100) + '%')
);

// Sync (if available)
const keySync = scrypt.syncScrypt(
  Buffer.from('password'),
  Buffer.from('salt'),
  16384, 8, 1, 32
);
