/**
 * @name Crypto inventory — PyKCS11 / PKCS#11 (Python)
 * @description Inventory of PyKCS11 library usage including PKCS#11 mechanism
 *              instantiation, key generation, and cryptographic session
 *              operations (encrypt, decrypt, sign, verify, digest).
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-pykcs11
 * @tags security
 */

import python
import lib.PyCryptoCommon

/**
 * Holds if `call` is a `PyKCS11.Mechanism(...)` or `Mechanism(...)` constructor.
 * The latter occurs after `from PyKCS11 import Mechanism`.
 */
predicate isMechanismCall(Call call) {
  isConstructorCall(call, "Mechanism") or
  isAttrCall(call, "PyKCS11", "Mechanism")
}

/**
 * Gets the algorithm name derived from a `CKM_*` constant reference that
 * appears as the first positional argument of a Mechanism call.
 *
 * The CKM constant name is normalised by stripping the "CKM_" prefix,
 * lowercasing, and replacing underscores with hyphens so that, for example,
 * `CKM_AES_GCM` becomes `"aes-gcm"` and `CKM_RSA_PKCS_KEY_PAIR_GEN` becomes
 * `"rsa-pkcs-key-pair-gen"`.
 *
 * Handles both forms:
 *   PyKCS11.CKM_AES_GCM   (attribute access)
 *   CKM_AES_GCM           (after `from PyKCS11 import *`)
 */
string mechanismAlgo(Call mechCall) {
  isMechanismCall(mechCall) and
  (
    // PyKCS11.CKM_*  — attribute access on the module
    exists(Attribute ckmAttr |
      mechCall.getPositionalArg(0) = ckmAttr and
      ckmAttr.getName().prefix(4) = "CKM_" and
      result = ckmAttr.getName().suffix(4).toLowerCase().replaceAll("_", "-")
    )
    or
    // CKM_*  — plain name after from-import
    exists(Name ckmName |
      mechCall.getPositionalArg(0) = ckmName and
      ckmName.getId().prefix(4) = "CKM_" and
      result = ckmName.getId().suffix(4).toLowerCase().replaceAll("_", "-")
    )
  )
}

from Call call, string algo, string api
where
  api = "PyKCS11" and
  (
    // ==========================================================================
    // Library initialisation
    // PyKCS11.PyKCS11Lib()  or  PyKCS11Lib()  [from PyKCS11 import PyKCS11Lib]
    // ==========================================================================
    (
      (
        isConstructorCall(call, "PyKCS11Lib") or
        isAttrCall(call, "PyKCS11", "PyKCS11Lib")
      ) and
      algo = "pkcs11-init"
    )

    or

    // ==========================================================================
    // Mechanism constructor — primary algorithm carrier in PKCS#11
    // PyKCS11.Mechanism(PyKCS11.CKM_AES_GCM, params)
    // Mechanism(CKM_RSA_PKCS, None)
    // ==========================================================================
    (
      isMechanismCall(call) and
      (
        exists(string mAlgo | mAlgo = mechanismAlgo(call) | algo = "pkcs11-mech-" + mAlgo)
        or
        (not exists(mechanismAlgo(call)) and algo = "unresolved")
      )
    )

    or

    // ==========================================================================
    // Session key-generation operations
    // session.generateKey(template)
    // session.generateKeyPair(pubTemplate, privTemplate, mechanism)
    // When the mechanism arg is an inline Mechanism(CKM_*) call the algorithm
    // is extracted; otherwise the operation type is recorded.
    // ==========================================================================

    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "generateKey") and
      (
        exists(Call mechCall, string mAlgo |
          (call.getPositionalArg(1) = mechCall or call.getPositionalArg(2) = mechCall) and
          mAlgo = mechanismAlgo(mechCall) and
          algo = "keygen-" + mAlgo
        )
        or
        (
          not exists(Call mechCall |
            (call.getPositionalArg(1) = mechCall or call.getPositionalArg(2) = mechCall) and
            exists(mechanismAlgo(mechCall))
          ) and
          algo = "unresolved"
        )
      )
    )

    or

    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "generateKeyPair") and
      (
        exists(Call mechCall, string mAlgo |
          (call.getPositionalArg(2) = mechCall or call.getPositionalArg(3) = mechCall) and
          mAlgo = mechanismAlgo(mechCall) and
          algo = "keygen-" + mAlgo
        )
        or
        (
          not exists(Call mechCall |
            (call.getPositionalArg(2) = mechCall or call.getPositionalArg(3) = mechCall) and
            exists(mechanismAlgo(mechCall))
          ) and
          algo = "unresolved"
        )
      )
    )

    or

    // ==========================================================================
    // Session encryption / decryption
    // session.encrypt(key, data, mechanism)
    // session.decrypt(key, data, mechanism)
    // ==========================================================================

    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (attr.getName() = "encrypt" or attr.getName() = "decrypt")
      ) and
      (
        exists(Call mechCall, string mAlgo |
          call.getPositionalArg(2) = mechCall and
          mAlgo = mechanismAlgo(mechCall) and
          exists(Attribute attr | call.getFunc() = attr |
            algo = attr.getName() + "-" + mAlgo
          )
        )
        or
        (
          not exists(Call mechCall |
            call.getPositionalArg(2) = mechCall and exists(mechanismAlgo(mechCall))
          ) and
          exists(Attribute attr | call.getFunc() = attr |
            algo = "unresolved"
          )
        )
      )
    )

    or

    // ==========================================================================
    // Session signing / verification
    // session.sign(key, data, mechanism)
    // session.verify(key, data, signature, mechanism)
    // ==========================================================================

    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (attr.getName() = "sign" or attr.getName() = "verify")
      ) and
      (
        // mechanism at position 2 (sign) or 3 (verify)
        exists(Call mechCall, string mAlgo |
          (call.getPositionalArg(2) = mechCall or call.getPositionalArg(3) = mechCall) and
          mAlgo = mechanismAlgo(mechCall) and
          exists(Attribute attr | call.getFunc() = attr |
            algo = attr.getName() + "-" + mAlgo
          )
        )
        or
        (
          not exists(Call mechCall |
            (call.getPositionalArg(2) = mechCall or call.getPositionalArg(3) = mechCall) and
            exists(mechanismAlgo(mechCall))
          ) and
          exists(Attribute attr | call.getFunc() = attr |
            algo = "unresolved"
          )
        )
      )
    )

    or

    // ==========================================================================
    // Session digest (hash)
    // session.digest(data, mechanism)
    // ==========================================================================

    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "digest") and
      (
        exists(Call mechCall, string mAlgo |
          call.getPositionalArg(1) = mechCall and
          mAlgo = mechanismAlgo(mechCall) and
          algo = "digest-" + mAlgo
        )
        or
        (
          not exists(Call mechCall |
            call.getPositionalArg(1) = mechCall and exists(mechanismAlgo(mechCall))
          ) and
          algo = "unresolved"
        )
      )
    )

    or

    // ==========================================================================
    // Key wrapping / unwrapping / derivation
    // session.wrapKey(wrapping_key, key, mechanism)
    // session.unwrapKey(wrapping_key, wrapped, template, mechanism)
    // session.deriveKey(base_key, template, mechanism)
    // ==========================================================================

    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          attr.getName() = "wrapKey" or
          attr.getName() = "unwrapKey" or
          attr.getName() = "deriveKey"
        )
      ) and
      (
        exists(Call mechCall, string mAlgo |
          (
            call.getPositionalArg(2) = mechCall or
            call.getPositionalArg(3) = mechCall
          ) and
          mAlgo = mechanismAlgo(mechCall) and
          exists(Attribute attr | call.getFunc() = attr |
            algo = attr.getName().toLowerCase() + "-" + mAlgo
          )
        )
        or
        (
          not exists(Call mechCall |
            (call.getPositionalArg(2) = mechCall or call.getPositionalArg(3) = mechCall) and
            exists(mechanismAlgo(mechCall))
          ) and
          algo = "unresolved"
        )
      )
    )

    or

    // ==========================================================================
    // Multi-part operations — Init/Update/Final patterns
    // session.encryptInit(key, mechanism)
    // session.encryptUpdate(data)
    // session.encryptFinal()
    // (also decryptInit/Update/Final, signInit/Update/Final, etc.)
    // ==========================================================================
    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "encryptInit"  and algo = "encrypt-init") or
          (attr.getName() = "encryptUpdate" and algo = "encrypt-update") or
          (attr.getName() = "encryptFinal" and algo = "encrypt-final") or
          (attr.getName() = "decryptInit"  and algo = "decrypt-init") or
          (attr.getName() = "decryptUpdate" and algo = "decrypt-update") or
          (attr.getName() = "decryptFinal" and algo = "decrypt-final") or
          (attr.getName() = "signInit"     and algo = "sign-init") or
          (attr.getName() = "signUpdate"   and algo = "sign-update") or
          (attr.getName() = "signFinal"    and algo = "sign-final") or
          (attr.getName() = "verifyInit"   and algo = "verify-init") or
          (attr.getName() = "verifyUpdate" and algo = "verify-update") or
          (attr.getName() = "verifyFinal"  and algo = "verify-final") or
          (attr.getName() = "digestInit"   and algo = "digest-init") or
          (attr.getName() = "digestUpdate" and algo = "digest-update") or
          (attr.getName() = "digestFinal"  and algo = "digest-final")
        )
      )
    )

    or

    // ==========================================================================
    // Random operations
    // session.generateRandom(length)
    // session.seedRandom(seed)
    // ==========================================================================
    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "generateRandom" and algo = "csprng-pkcs11-random") or
          (attr.getName() = "seedRandom"     and algo = "pkcs11-seed-random")
        )
      )
    )

    or

    // ==========================================================================
    // Specialized mechanism classes (PyKCS11 v1.5+)
    // AES_GCM_Mechanism, RSAOAEPMechanism, RSA_PSS_Mechanism, etc.
    // ==========================================================================
    (
      (
        isConstructorCall(call, "AES_GCM_Mechanism") and algo = "pkcs11-aes-gcm-mech"
      ) or (
        isConstructorCall(call, "RSAOAEPMechanism") and algo = "pkcs11-rsa-oaep-mech"
      ) or (
        isConstructorCall(call, "RSA_PSS_Mechanism") and algo = "pkcs11-rsa-pss-mech"
      ) or (
        isConstructorCall(call, "ECDH1_DERIVE_Mechanism") and algo = "pkcs11-ecdh1-derive-mech"
      ) or (
        isConstructorCall(call, "EDDSA_Mechanism") and algo = "pkcs11-eddsa-mech"
      ) or (
        isConstructorCall(call, "AES_CTR_Mechanism") and algo = "pkcs11-aes-ctr-mech"
      ) or (
        isConstructorCall(call, "CONCATENATE_BASE_AND_DATA_Mechanism") and algo = "pkcs11-concat-base-data-mech"
      ) or (
        isConstructorCall(call, "CONCATENATE_BASE_AND_KEY_Mechanism") and algo = "pkcs11-concat-base-key-mech"
      ) or (
        isConstructorCall(call, "CONCATENATE_DATA_AND_BASE_Mechanism") and algo = "pkcs11-concat-data-base-mech"
      ) or (
        isConstructorCall(call, "EXTRACT_KEY_FROM_KEY_Mechanism") and algo = "pkcs11-extract-key-mech"
      ) or (
        isConstructorCall(call, "XOR_BASE_AND_DATA_Mechanism") and algo = "pkcs11-xor-base-data-mech"
      )
    )

    or

    // ==========================================================================
    // Session.digestSession(mecha) — returns DigestSession for multi-part hash
    // DigestSession.digestKey(handle) — C_DigestKey (digests key material)
    // ==========================================================================
    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "digestSession" and algo = "digest-session") or
          (attr.getName() = "digestKey" and algo = "digest-key")
        )
      )
    )

    or

    // ==========================================================================
    // Mechanism via keyword arg: session.encrypt(key, data, mecha=Mechanism(...))
    // ==========================================================================
    (
      fileImportsPyKCS11(call.getLocation().getFile()) and
      exists(Keyword kw, Call mechCall |
        call.getAKeyword() = kw and
        kw.getArg() = "mecha" and
        kw.getValue() = mechCall and
        exists(string mAlgo | mAlgo = mechanismAlgo(mechCall) |
          algo = "pkcs11-mecha-kw-" + mAlgo
        )
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
