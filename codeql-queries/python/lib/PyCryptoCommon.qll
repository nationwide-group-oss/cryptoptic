/**
 * @name PyCryptoCommon — shared predicates for Python CBOM query pack
 * @description Common helper predicates for argument resolution and pattern
 *              matching used across all Python CBOM queries.
 */

import python

// =============================================================================
// Attribute-Call Helpers
// =============================================================================

/**
 * Holds if `call` is `modName.methodName(...)` where `modName` is a simple
 * Name node (variable reference).
 *
 * Example: hashlib.sha256(data)
 *   modName = "hashlib", methodName = "sha256"
 */
predicate isAttrCall(Call call, string modName, string methodName) {
  exists(Attribute attr, Name obj |
    call.getFunc() = attr and
    attr.getObject() = obj and
    obj.getId() = modName and
    attr.getName() = methodName
  )
}

/**
 * Holds if `call` is `ClassName.methodName(...)` where ClassName is a Name.
 * Alias for isAttrCall to improve readability in class-method contexts.
 */
predicate isClassMethodCall(Call call, string className, string methodName) {
  isAttrCall(call, className, methodName)
}

/**
 * Holds if `call` is `ClassName(...)` where the callee is a simple Name.
 */
predicate isConstructorCall(Call call, string className) {
  call.getFunc().(Name).getId() = className
}

// =============================================================================
// Argument Value Extraction
// =============================================================================

/**
 * Gets the string value of keyword argument `kwName`.
 */
string getKeywordString(Call call, string kwName) {
  exists(Keyword kw, StringLiteral s |
    call.getAKeyword() = kw and
    kw.getArg() = kwName and
    kw.getValue() = s and
    result = s.getS()
  )
}

/**
 * Gets the string value of positional argument at index `i`.
 */
string getPositionalString(Call call, int i) {
  result = call.getPositionalArg(i).(StringLiteral).getS()
}

/**
 * Gets the attribute name from keyword `kwName` when its value is a plain
 * Attribute reference (not a call).
 *
 * Example: hmac.new(key, msg, digestmod=hashlib.sha256)
 *   Returns "sha256"
 */
string getKeywordAttrRefName(Call call, string kwName) {
  exists(Keyword kw, Attribute attr |
    call.getAKeyword() = kw and
    kw.getArg() = kwName and
    kw.getValue() = attr and
    result = attr.getName()
  )
}

/**
 * Gets the function name from keyword `kwName` when its value is a Call to
 * an Attribute.
 *
 * Example: PBKDF2HMAC(algorithm=hashes.SHA256(), ...)
 *   Returns "SHA256"
 */
string getKeywordAttrCallName(Call call, string kwName) {
  exists(Keyword kw, Call inner, Attribute attr |
    call.getAKeyword() = kw and
    kw.getArg() = kwName and
    kw.getValue() = inner and
    inner.getFunc() = attr and
    result = attr.getName()
  )
}

/**
 * Gets the function name from keyword `kwName` when its value is a Call to
 * a plain Name.
 *
 * Example: PBKDF2HMAC(algorithm=SHA256(), ...)
 *   Returns "SHA256"
 */
string getKeywordNameCallId(Call call, string kwName) {
  exists(Keyword kw, Call inner, Name fn |
    call.getAKeyword() = kw and
    kw.getArg() = kwName and
    kw.getValue() = inner and
    inner.getFunc() = fn and
    result = fn.getId()
  )
}

/**
 * Resolves a hash algorithm name from keyword `kwName` that may be either
 * `hashes.SHA256()` (Attribute call) or `SHA256()` (Name call).
 * Returns the name in lowercase.
 */
string resolveHashAlgoKw(Call call, string kwName) {
  result = getKeywordAttrCallName(call, kwName).toLowerCase()
  or
  result = getKeywordNameCallId(call, kwName).toLowerCase()
}

/**
 * Gets the attribute name of positional arg `i` when it is a plain Attribute
 * reference (not a call).
 *
 * Example: hmac.new(key, msg, hashlib.sha256)  — arg 2 is Attribute
 *   Returns "sha256"
 */
string getPositionalAttrName(Call call, int i) {
  result = call.getPositionalArg(i).(Attribute).getName()
}

/**
 * Gets the function name of positional arg `i` when it is a Call to an
 * Attribute.
 *
 * Example: ec.generate_private_key(ec.SECP256R1())  — arg 0 is Call(Attr)
 *   Returns "SECP256R1"
 */
string getPositionalAttrCallName(Call call, int i) {
  exists(Call inner, Attribute attr |
    call.getPositionalArg(i) = inner and
    inner.getFunc() = attr and
    result = attr.getName()
  )
}

/**
 * Gets the Name id of positional arg `i` when it is a Call to a plain Name.
 *
 * Example: generate_private_key(SECP256R1())  — arg 0 is Call(Name)
 *   Returns "SECP256R1"
 */
string getPositionalNameCallId(Call call, int i) {
  exists(Call inner, Name fn |
    call.getPositionalArg(i) = inner and
    inner.getFunc() = fn and
    result = fn.getId()
  )
}

// =============================================================================
// File-Level Library-Usage Guards
// =============================================================================
// These predicates check whether a file contains evidence of a specific
// library being used.  They are applied as guards on generic method-name
// matches (e.g. .encrypt(), .sign()) to prevent cross-library false positives.

/**
 * Holds when file `f` contains evidence of PyKCS11 usage — a `PyKCS11Lib`
 * constructor, a `PyKCS11.*` attribute access, or a `CKM_*` constant
 * reference.
 */
predicate fileImportsPyKCS11(File f) {
  exists(Name n | n.getLocation().getFile() = f and n.getId() = "PyKCS11Lib")
  or
  exists(Attribute a |
    a.getLocation().getFile() = f and a.getObject().(Name).getId() = "PyKCS11"
  )
  or
  exists(Name n | n.getLocation().getFile() = f and n.getId().prefix(4) = "CKM_")
}

/**
 * Holds when file `f` contains evidence of python-gnupg usage — a
 * `gnupg.GPG()` attribute call or a reference to the `gnupg` module name.
 */
predicate fileImportsGnupg(File f) {
  exists(Attribute a |
    a.getLocation().getFile() = f and a.getObject().(Name).getId() = "gnupg"
  )
}

/**
 * Holds when file `f` contains Authlib-specific JOSE constructs — an
 * Authlib-style `jwt.encode()` (header Dict as first arg, no `algorithm=`
 * keyword) or Authlib key-class / JWS / JWE constructor usage.
 */
predicate fileUsesAuthlib(File f) {
  exists(Call c | c.getLocation().getFile() = f |
    // Authlib-style jwt.encode: first arg is header Dict, no algorithm= kw
    (
      isAttrCall(c, "jwt", "encode") and
      c.getPositionalArg(0) instanceof Dict and
      not exists(getKeywordString(c, "algorithm"))
    )
    or
    // Authlib-specific constructors
    c.getFunc().(Name).getId() = "JsonWebSignature" or
    c.getFunc().(Name).getId() = "JsonWebEncryption" or
    // Authlib key classes — generate_key / import_key
    isAttrCall(c, "JsonWebKey", "generate_key") or
    isAttrCall(c, "JsonWebKey", "import_key") or
    isAttrCall(c, "OctKey", "generate_key") or
    isAttrCall(c, "OctKey", "import_key") or
    isAttrCall(c, "OKPKey", "generate_key") or
    isAttrCall(c, "OKPKey", "import_key")
  )
}

/**
 * Holds when file `f` contains python-jose-specific constructs — calls to
 * `jws.sign()`, `jws.verify()`, `jwe.encrypt()`, or `jwe.decrypt()` which
 * are not available in PyJWT.
 */
predicate fileUsesPythonJose(File f) {
  exists(Call c | c.getLocation().getFile() = f |
    isAttrCall(c, "jws", "sign") or
    isAttrCall(c, "jws", "verify") or
    isAttrCall(c, "jwe", "encrypt") or
    isAttrCall(c, "jwe", "decrypt")
  )
}

/**
 * Holds when file `f` contains evidence of pyca/cryptography usage — imports
 * from cryptography.hazmat, hazmat references, or cryptography-specific classes.
 */
predicate fileImportsCryptography(File f) {
  exists(Attribute a |
    a.getLocation().getFile() = f and
    (
      a.getObject().(Name).getId() = "hashes" or
      a.getObject().(Name).getId() = "serialization" or
      a.getObject().(Name).getId() = "padding" or
      a.getObject().(Name).getId() = "ec" or
      a.getObject().(Name).getId() = "rsa" or
      a.getObject().(Name).getId() = "dsa" or
      a.getObject().(Name).getId() = "dh" or
      a.getObject().(Name).getId() = "algorithms" or
      a.getObject().(Name).getId() = "modes" or
      a.getObject().toString().matches("%hazmat%")
    )
  )
  or
  exists(Name n |
    n.getLocation().getFile() = f and
    (
      n.getId() = "Fernet" or
      n.getId() = "AESGCM" or
      n.getId() = "AESCCM" or
      n.getId() = "ChaCha20Poly1305" or
      n.getId() = "PBKDF2HMAC" or
      n.getId() = "Scrypt" or
      n.getId() = "HKDF"
    )
  )
  or
  f.toString().matches("%cryptography%")
}

/**
 * Holds when file `f` contains evidence of Django usage.
 */
predicate fileImportsDjango(File f) {
  exists(Attribute a |
    a.getLocation().getFile() = f and
    a.getObject().(Name).getId() = "django"
  )
  or
  f.toString().matches("%django%")
  or
  exists(Name n |
    n.getLocation().getFile() = f and
    (
      n.getId() = "CsrfViewMiddleware" or
      n.getId() = "SessionStore" or
      n.getId().matches("%PasswordHasher%")
    )
  )
}

/**
 * Holds when file `f` contains evidence of itsdangerous usage.
 */
predicate fileImportsItsdangerous(File f) {
  exists(Attribute a |
    a.getLocation().getFile() = f and
    a.getObject().(Name).getId() = "itsdangerous"
  )
  or
  exists(Name n |
    n.getLocation().getFile() = f and
    (
      n.getId() = "URLSafeTimedSerializer" or
      n.getId() = "URLSafeSerializer" or
      n.getId() = "TimestampSigner" or
      n.getId() = "Signer"
    )
  ) and
  // Disambiguate from Django Signer — require itsdangerous-specific names
  (
    exists(Name n2 |
      n2.getLocation().getFile() = f and
      (
        n2.getId() = "URLSafeTimedSerializer" or
        n2.getId() = "URLSafeSerializer" or
        n2.getId() = "itsdangerous"
      )
    )
    or
    f.toString().matches("%itsdangerous%")
  )
}

/**
 * Holds when file `f` contains evidence of passlib usage.
 */
predicate fileImportsPasslib(File f) {
  exists(Attribute a |
    a.getLocation().getFile() = f and
    (
      a.getObject().(Name).getId() = "passlib" or
      a.getObject().toString().matches("%passlib%")
    )
  )
  or
  exists(Name n |
    n.getLocation().getFile() = f and
    n.getId() = "CryptContext"
  )
  or
  f.toString().matches("%passlib%")
}

/**
 * Holds when file `f` contains evidence of PyJWT usage — jwt imports or
 * jwt-related class references.
 */
predicate fileImportsJwt(File f) {
  exists(Attribute a |
    a.getLocation().getFile() = f and
    a.getObject().(Name).getId() = "jwt"
  )
  or
  exists(Name n |
    n.getLocation().getFile() = f and
    (
      n.getId() = "PyJWS" or
      n.getId() = "PyJWT" or
      n.getId() = "RSAAlgorithm" or
      n.getId() = "ECAlgorithm" or
      n.getId() = "HMACAlgorithm"
    )
  )
}

// =============================================================================
// Enhanced Argument Value Resolution (Multi-Strategy)
// =============================================================================
// These predicates implement deeper resolution of argument values similar to
// the JavaScript CryptoCommon.qll multi-priority approach.

/**
 * Priority 1 helper: holds when a direct string literal or simple variable
 * assignment resolves positional argument `i`.
 */
private predicate hasPriority1ResultPositional(Call call, int i) {
  exists(call.getPositionalArg(i).(StringLiteral))
  or
  exists(Name argName, AssignStmt assign |
    call.getPositionalArg(i) = argName and
    assign.getScope() = call.getScope() and
    assign.getATarget().(Name).getId() = argName.getId() and
    assign.getValue() instanceof StringLiteral
  )
}

/**
 * Gets the resolved string value of positional argument `i` using a multi-
 * priority strategy. Returns the value lowercased.
 *
 * Resolution strategies (in priority order):
 *   P1: Direct string literal or local variable assignment.
 *   P2: Python ternary (IfExp) — extracts BOTH branches.
 *   P3: Dictionary value enumeration — enumerates all string values in a dict.
 *   P4: Function default parameter values.
 *   P5: Cross-function call-site argument tracking (one level).
 */
string resolvePositionalArg(Call call, int i) {
  // Priority 1: direct string literal
  result = call.getPositionalArg(i).(StringLiteral).getS().toLowerCase()
  or
  // Priority 1b: local variable assignment in same scope
  (
    not exists(call.getPositionalArg(i).(StringLiteral)) and
    exists(Name argName, AssignStmt assign, StringLiteral lit |
      call.getPositionalArg(i) = argName and
      assign.getScope() = call.getScope() and
      assign.getATarget().(Name).getId() = argName.getId() and
      assign.getValue() = lit and
      result = lit.getS().toLowerCase()
    )
  )
  or
  // Priority 2: Python ternary — `x if cond else y`
  (
    not hasPriority1ResultPositional(call, i) and
    exists(IfExp ternary |
      (
        call.getPositionalArg(i) = ternary
        or
        exists(Name argName, AssignStmt assign |
          call.getPositionalArg(i) = argName and
          assign.getScope() = call.getScope() and
          assign.getATarget().(Name).getId() = argName.getId() and
          assign.getValue() = ternary
        )
      ) and
      (
        result = ternary.getBody().(StringLiteral).getS().toLowerCase()
        or
        result = ternary.getOrelse().(StringLiteral).getS().toLowerCase()
      )
    )
  )
  or
  // Priority 3: Dictionary value enumeration
  // When arg is a subscript on a dict: ALGO_MAP[key]
  (
    not hasPriority1ResultPositional(call, i) and
    not exists(IfExp ternary |
      call.getPositionalArg(i) = ternary or
      exists(Name n, AssignStmt a |
        call.getPositionalArg(i) = n and
        a.getScope() = call.getScope() and
        a.getATarget().(Name).getId() = n.getId() and
        a.getValue() = ternary
      )
    ) and
    exists(Subscript sub, Name dictName, AssignStmt dictAssign, Dict dictLit |
      (
        call.getPositionalArg(i) = sub
        or
        exists(Name argName, AssignStmt assign |
          call.getPositionalArg(i) = argName and
          assign.getScope() = call.getScope() and
          assign.getATarget().(Name).getId() = argName.getId() and
          assign.getValue() = sub
        )
      ) and
      sub.getObject() = dictName and
      dictAssign.getScope() = call.getScope() and
      dictAssign.getATarget().(Name).getId() = dictName.getId() and
      dictAssign.getValue() = dictLit and
      exists(StringLiteral val |
        val = dictLit.getAValue() and
        result = val.getS().toLowerCase()
      )
    )
  )
  or
  // Priority 4: Function default parameter values
  (
    not hasPriority1ResultPositional(call, i) and
    not exists(IfExp ternary |
      call.getPositionalArg(i) = ternary or
      exists(Name n, AssignStmt a |
        call.getPositionalArg(i) = n and
        a.getScope() = call.getScope() and
        a.getATarget().(Name).getId() = n.getId() and
        a.getValue() = ternary
      )
    ) and
    exists(Name argName, Function fn, Parameter param |
      call.getPositionalArg(i) = argName and
      fn = call.getScope() and
      param = fn.getAnArg() and
      param.(Name).getId() = argName.getId() and
      result = param.getDefault().(StringLiteral).getS().toLowerCase()
    )
  )
  or
  // Priority 5: Cross-function call-site argument tracking (one level)
  (
    not hasPriority1ResultPositional(call, i) and
    not exists(IfExp ternary |
      call.getPositionalArg(i) = ternary or
      exists(Name n, AssignStmt a |
        call.getPositionalArg(i) = n and
        a.getScope() = call.getScope() and
        a.getATarget().(Name).getId() = n.getId() and
        a.getValue() = ternary
      )
    ) and
    exists(Name argName, Function fn, int paramIndex, Call callSite |
      call.getPositionalArg(i) = argName and
      fn = call.getScope() and
      fn.getArg(paramIndex).(Name).getId() = argName.getId() and
      // Find call sites of this function in the same file
      callSite.getLocation().getFile() = call.getLocation().getFile() and
      callSite.getFunc().(Name).getId() = fn.getName() and
      result = callSite.getPositionalArg(paramIndex).(StringLiteral).getS().toLowerCase()
    )
  )
}

/**
 * Similar to resolvePositionalArg but for keyword arguments.
 * Gets the resolved string value of keyword argument `kwName` using multi-
 * priority strategy. Returns the value lowercased.
 */
string resolveKeywordArg(Call call, string kwName) {
  // Priority 1: direct string literal in keyword
  result = getKeywordString(call, kwName).toLowerCase()
  or
  // Priority 1b: keyword value is a variable — trace local assignment
  (
    not exists(getKeywordString(call, kwName)) and
    exists(Keyword kw, Name valName, AssignStmt assign, StringLiteral lit |
      call.getAKeyword() = kw and
      kw.getArg() = kwName and
      kw.getValue() = valName and
      assign.getScope() = call.getScope() and
      assign.getATarget().(Name).getId() = valName.getId() and
      assign.getValue() = lit and
      result = lit.getS().toLowerCase()
    )
  )
  or
  // Priority 2: keyword value is a ternary
  (
    not exists(getKeywordString(call, kwName)) and
    not exists(Keyword kw, Name valName, AssignStmt assign |
      call.getAKeyword() = kw and kw.getArg() = kwName and
      kw.getValue() = valName and
      assign.getScope() = call.getScope() and
      assign.getATarget().(Name).getId() = valName.getId() and
      assign.getValue() instanceof StringLiteral
    ) and
    exists(Keyword kw, IfExp ternary |
      call.getAKeyword() = kw and
      kw.getArg() = kwName and
      (
        kw.getValue() = ternary
        or
        exists(Name valName, AssignStmt assign |
          kw.getValue() = valName and
          assign.getScope() = call.getScope() and
          assign.getATarget().(Name).getId() = valName.getId() and
          assign.getValue() = ternary
        )
      ) and
      (
        result = ternary.getBody().(StringLiteral).getS().toLowerCase()
        or
        result = ternary.getOrelse().(StringLiteral).getS().toLowerCase()
      )
    )
  )
}

/**
 * Resolves a hash algorithm argument that may be passed as:
 *   - hashes.SHA256() (Attribute call)
 *   - SHA256() (Name call)
 *   - A variable assigned to one of the above
 *
 * Enhanced version of resolveHashAlgoKw that also tracks local variable
 * assignments.
 */
string resolveHashAlgoEnhanced(Call call, string kwName) {
  // Direct: hashes.SHA256() or SHA256()
  result = resolveHashAlgoKw(call, kwName)
  or
  // Variable tracking: algo_obj = hashes.SHA256(); func(algorithm=algo_obj)
  (
    not exists(resolveHashAlgoKw(call, kwName)) and
    exists(Keyword kw, Name valName, AssignStmt assign |
      call.getAKeyword() = kw and
      kw.getArg() = kwName and
      kw.getValue() = valName and
      assign.getScope() = call.getScope() and
      assign.getATarget().(Name).getId() = valName.getId() and
      (
        // assigned value is hashes.X()
        exists(Call inner, Attribute attr |
          assign.getValue() = inner and
          inner.getFunc() = attr and
          result = attr.getName().toLowerCase()
        )
        or
        // assigned value is X()
        exists(Call inner, Name fn |
          assign.getValue() = inner and
          inner.getFunc() = fn and
          result = fn.getId().toLowerCase()
        )
      )
    )
  )
}

/**
 * Enhanced resolution for positional hash algorithm arguments.
 * Tracks local variable assignments in addition to direct Attribute/Name calls.
 */
string resolveHashAlgoPositionalEnhanced(Call call, int i) {
  // Direct: hashes.SHA256() or SHA256() at position i
  result = getPositionalAttrCallName(call, i).toLowerCase()
  or
  result = getPositionalNameCallId(call, i).toLowerCase()
  or
  // Variable tracking: algo_obj = hashes.SHA256(); func(algo_obj)
  (
    not exists(getPositionalAttrCallName(call, i)) and
    not exists(getPositionalNameCallId(call, i)) and
    exists(Name argName, AssignStmt assign |
      call.getPositionalArg(i) = argName and
      assign.getScope() = call.getScope() and
      assign.getATarget().(Name).getId() = argName.getId() and
      (
        exists(Call inner, Attribute attr |
          assign.getValue() = inner and
          inner.getFunc() = attr and
          result = attr.getName().toLowerCase()
        )
        or
        exists(Call inner, Name fn |
          assign.getValue() = inner and
          inner.getFunc() = fn and
          result = fn.getId().toLowerCase()
        )
      )
    )
  )
}


