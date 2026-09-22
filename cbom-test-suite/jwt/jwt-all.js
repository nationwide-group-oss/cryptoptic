/**
 * CBOM Test Suite — JWT / JWE / JWS Libraries
 * NOT COVERED by current queries. Critical gap.
 */

// =============================================================================
// jsonwebtoken (~15M/wk) — most popular JWT library
// =============================================================================
const jwt = require('jsonwebtoken');

// Sign with HMAC (symmetric)
const tokenHS256 = jwt.sign({ userId: 1 }, 'secret', { algorithm: 'HS256' });
const tokenHS384 = jwt.sign({ userId: 1 }, 'secret', { algorithm: 'HS384' });
const tokenHS512 = jwt.sign({ userId: 1 }, 'secret', { algorithm: 'HS512' });

// Default algorithm (HS256)
const tokenDefault = jwt.sign({ userId: 1 }, 'secret');

// Sign with RSA
const tokenRS256 = jwt.sign({ userId: 1 }, rsaPrivateKey, { algorithm: 'RS256' });
const tokenRS384 = jwt.sign({ userId: 1 }, rsaPrivateKey, { algorithm: 'RS384' });
const tokenRS512 = jwt.sign({ userId: 1 }, rsaPrivateKey, { algorithm: 'RS512' });

// Sign with RSA-PSS
const tokenPS256 = jwt.sign({ userId: 1 }, rsaPrivateKey, { algorithm: 'PS256' });
const tokenPS384 = jwt.sign({ userId: 1 }, rsaPrivateKey, { algorithm: 'PS384' });
const tokenPS512 = jwt.sign({ userId: 1 }, rsaPrivateKey, { algorithm: 'PS512' });

// Sign with ECDSA
const tokenES256 = jwt.sign({ userId: 1 }, ecPrivateKey, { algorithm: 'ES256' });
const tokenES384 = jwt.sign({ userId: 1 }, ecPrivateKey, { algorithm: 'ES384' });
const tokenES512 = jwt.sign({ userId: 1 }, ecPrivateKey, { algorithm: 'ES512' });

// Sign with EdDSA
const tokenEdDSA = jwt.sign({ userId: 1 }, ed25519PrivateKey, { algorithm: 'EdDSA' });

// Verify
const decoded = jwt.verify(tokenHS256, 'secret');
const decodedRS = jwt.verify(tokenRS256, rsaPublicKey, { algorithms: ['RS256'] });
const decodedES = jwt.verify(tokenES256, ecPublicKey, { algorithms: ['ES256'] });
const decodedMulti = jwt.verify(token, pubKey, { algorithms: ['RS256', 'RS384', 'ES256'] });

// Verify with specific algorithm constraint (security best practice)
const decoded2 = jwt.verify(token, secret, { algorithms: ['HS256'] });

// Decode without verification (insecure — but used for inspection)
const unverified = jwt.decode(token, { complete: true });

// Via variable
const algo = 'RS256';
const tokenVar = jwt.sign({ data: 'test' }, rsaPrivateKey, { algorithm: algo });

// Via options object
const jwtOpts = { algorithm: 'ES256', expiresIn: '1h' };
const tokenOpts = jwt.sign({ userId: 1 }, ecPrivateKey, jwtOpts);

// =============================================================================
// jose (~8M/wk) — modern JOSE library (JWS, JWE, JWK, JWT)
// =============================================================================
import { SignJWT, jwtVerify, CompactEncrypt, compactDecrypt } from 'jose';
import { generateKeyPair, importPKCS8, importSPKI, importJWK, exportJWK } from 'jose';
import { EncryptJWT, jwtDecrypt } from 'jose';
import { FlattenedSign, FlattenedEncrypt } from 'jose';
import { GeneralSign, GeneralEncrypt } from 'jose';

// Sign JWT
const jwtSigned = await new SignJWT({ userId: 1 })
  .setProtectedHeader({ alg: 'ES256' })
  .setIssuedAt()
  .setExpirationTime('2h')
  .sign(ecPrivateKey);

// Various algorithms
const jwtRS256 = await new SignJWT({ data: 'test' })
  .setProtectedHeader({ alg: 'RS256' })
  .sign(rsaPrivKey);

const jwtPS256 = await new SignJWT({ data: 'test' })
  .setProtectedHeader({ alg: 'PS256' })
  .sign(rsaPrivKey);

const jwtEdDSA = await new SignJWT({ data: 'test' })
  .setProtectedHeader({ alg: 'EdDSA' })
  .sign(ed25519PrivKey);

const jwtHS256 = await new SignJWT({ data: 'test' })
  .setProtectedHeader({ alg: 'HS256' })
  .sign(hmacSecret);

// Verify JWT
const { payload, protectedHeader } = await jwtVerify(jwtSigned, ecPublicKey);
const { payload: p2 } = await jwtVerify(jwtRS256, rsaPubKey, { algorithms: ['RS256'] });

// JWE — Encrypt JWT
const jweToken = await new EncryptJWT({ secret: 'data' })
  .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
  .encrypt(rsaPublicKey);

const jweA128 = await new EncryptJWT({ secret: 'data' })
  .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A128CBC-HS256' })
  .encrypt(rsaPublicKey);

const jweEcdh = await new EncryptJWT({ secret: 'data' })
  .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
  .encrypt(ecPublicKey);

const jweDir = await new EncryptJWT({ secret: 'data' })
  .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
  .encrypt(symmetricKey);

const jweKw = await new EncryptJWT({ secret: 'data' })
  .setProtectedHeader({ alg: 'A256KW', enc: 'A256GCM' })
  .encrypt(kekKey);

// Decrypt JWE
const { payload: jwePayload } = await jwtDecrypt(jweToken, rsaPrivateKey);

// Compact JWE
const compactJwe = await new CompactEncrypt(new TextEncoder().encode('secret'))
  .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
  .encrypt(rsaPublicKey);
const { plaintext } = await compactDecrypt(compactJwe, rsaPrivateKey);

// Key generation
const rsaKeyPair = await generateKeyPair('RS256');
const ecKeyPair = await generateKeyPair('ES256');
const edKeyPair = await generateKeyPair('EdDSA');
const psKeyPair = await generateKeyPair('PS256');

// Key import/export
const privKey = await importPKCS8(pkcs8Pem, 'RS256');
const pubKey = await importSPKI(spkiPem, 'RS256');
const exported = await exportJWK(privKey);

// =============================================================================
// passport-jwt (Express.js middleware)
// =============================================================================
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'jwt-secret',
  algorithms: ['HS256'],
};

passport.use(new JwtStrategy(jwtOptions, (payload, done) => {
  return done(null, payload);
}));

// With RSA
const jwtOptionsRsa = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: rsaPublicKey,
  algorithms: ['RS256'],
};
passport.use('jwt-rsa', new JwtStrategy(jwtOptionsRsa, (payload, done) => {
  return done(null, payload);
}));

// =============================================================================
// express-jwt (Express.js middleware)
// =============================================================================
const { expressjwt } = require('express-jwt');

// HMAC
const jwtMiddleware = expressjwt({
  secret: 'shared-secret',
  algorithms: ['HS256']
});

// RSA
const jwtMiddlewareRsa = expressjwt({
  secret: rsaPublicKey,
  algorithms: ['RS256']
});

// Multiple algorithms
const jwtMiddlewareMulti = expressjwt({
  secret: 'secret',
  algorithms: ['HS256', 'HS384']
});
