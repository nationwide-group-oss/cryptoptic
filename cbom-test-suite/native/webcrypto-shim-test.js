/**
 * CBOM Test Suite — webcrypto-shim polyfill detection
 * When this import is present, subtle.* calls should be attributed to "webcrypto-shim"
 */
import 'webcrypto-shim';

// These should all be attributed to "webcrypto-shim" not "webcrypto"
crypto.subtle.digest('SHA-256', new Uint8Array([1, 2, 3]));
crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, key, data);
crypto.subtle.sign('ECDSA', ecKey, data);
crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
crypto.getRandomValues(new Uint8Array(32));
crypto.randomUUID();
