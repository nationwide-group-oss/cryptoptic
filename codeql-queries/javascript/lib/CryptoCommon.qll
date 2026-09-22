/**
 * @name CryptoCommon — shared predicates for CBOM query pack
 * @description Common helper predicates for argument resolution, module import
 *              tracking, and WebCrypto detection used across all CBOM queries.
 */

import javascript

// =============================================================================
// Module Import Helpers
// =============================================================================

/**
 * Holds if `call` is a method call `moduleName.methodName(...)` where
 * `moduleName` was imported via require() or ESM import.
 *
 * Covers:
 *   const mod = require('pkg'); mod.method(...)
 *   import mod from 'pkg'; mod.method(...)
 *   import * as mod from 'pkg'; mod.method(...)
 */
predicate isModuleMethodCall(InvokeExpr call, string moduleName, string methodName) {
  exists(DataFlow::SourceNode mod |
    mod = DataFlow::moduleImport(moduleName) and
    call = mod.getAMemberCall(methodName).asExpr()
  )
}

/**
 * Holds if `call` is a call to a named export from a module.
 *
 * Covers:
 *   import { sha256 } from '@noble/hashes/sha256'; sha256(data)
 *   const { sha256 } = require('@noble/hashes/sha256'); sha256(data)
 */
predicate isNamedImportCall(InvokeExpr call, string moduleName, string exportName) {
  exists(DataFlow::SourceNode member |
    member = DataFlow::moduleMember(moduleName, exportName) and
    call = member.getACall().asExpr()
  )
}

/**
 * Holds if `call` is `new ClassName(...)` where `ClassName` was imported from `moduleName`.
 *
 * Covers:
 *   const { SomeClass } = require('pkg'); new SomeClass(...)
 *   import SomeClass from 'pkg'; new SomeClass(...)
 */
predicate isModuleConstructorCall(InvokeExpr call, string moduleName, string exportName) {
  call instanceof NewExpr and
  exists(DataFlow::SourceNode member |
    (
      member = DataFlow::moduleMember(moduleName, exportName)
      or
      member = DataFlow::moduleImport(moduleName).getAPropertyRead(exportName)
    ) and
    call.getCallee().flow().getALocalSource() = member
  )
}

/**
 * Holds if the file containing `call` has an import/require of the given module.
 * Weaker check — useful when paired with callee-name matching for disambiguation.
 */
predicate fileImportsModule(InvokeExpr call, string moduleName) {
  exists(DataFlow::SourceNode mod |
    mod = DataFlow::moduleImport(moduleName) and
    mod.getFile() = call.getFile()
  )
}

/**
 * Gets a DataFlow::SourceNode for the given module import in the same file as `call`.
 */
DataFlow::SourceNode getModuleImport(InvokeExpr call, string moduleName) {
  result = DataFlow::moduleImport(moduleName) and
  result.getFile() = call.getFile()
}

// =============================================================================
// Chained Property Access Helpers
// =============================================================================

/**
 * Holds if `call` is a chained method call like `mod.a.b.method(...)`.
 * Tracks through property reads on a module import.
 *
 * Example: forge.md.sha256.create()
 *   moduleName = "node-forge"
 *   chain = ["md", "sha256"]
 *   methodName = "create"
 */
predicate isChainedModuleCall(InvokeExpr call, string moduleName, string prop1, string prop2, string methodName) {
  exists(DataFlow::SourceNode mod |
    mod = DataFlow::moduleImport(moduleName) and
    call = mod.getAPropertyRead(prop1).getAPropertyRead(prop2).getAMemberCall(methodName).asExpr()
  )
}

/**
 * Two-level chain: mod.a.method(...)
 */
predicate isChainedModuleCall2(InvokeExpr call, string moduleName, string prop1, string methodName) {
  exists(DataFlow::SourceNode mod |
    mod = DataFlow::moduleImport(moduleName) and
    call = mod.getAPropertyRead(prop1).getAMemberCall(methodName).asExpr()
  )
}

// =============================================================================
// Global Variable / Script-Tag Library Helpers
// =============================================================================

/**
 * Holds if `expr` refers to a "forge" object, whether obtained via module import
 * or via a global/window/parent/top reference.
 *
 * Matches:
 *   var forge = require('node-forge');    → module import
 *   var forge = top.forge;               → global via top
 *   var forge = window.forge;            → global via window
 *   var forge = parent.forge;            → global via parent
 *   var forge = globalThis.forge;        → global via globalThis
 *   forge.cipher.createCipher(...)       → bare global
 */
predicate isForgeRef(Expr expr) {
  // Module import (existing path)
  expr.flow().getALocalSource() = DataFlow::moduleImport("node-forge")
  or
  // Variable named "forge" — covers: var forge = top.forge; ... forge.cipher.createCipher(...)
  expr.(VarRef).getName() = "forge"
  or
  // Property access ending in "forge" on common global objects:
  // top.forge, window.forge, parent.forge, self.forge, globalThis.forge
  exists(PropAccess pa |
    pa = expr and
    pa.getPropertyName() = "forge" and
    pa.getBase().(VarRef).getName() = ["top", "window", "parent", "self", "globalThis"]
  )
}

/**
 * Gets a MethodCallExpr that is a call on forge.X.method() where X is a
 * known forge subsystem (cipher, md, hmac, pki, pkcs5, random, etc.)
 * and the forge reference is detected by isForgeRef.
 *
 * Example: forge.cipher.createCipher('AES-CBC', key)
 *   subsystem = "cipher", methodName = "createCipher"
 *
 * This handles BOTH module imports and global variable patterns.
 */
predicate isForgeSubsystemCall(InvokeExpr call, string subsystem, string methodName) {
  exists(MethodCallExpr mc, PropAccess receiver |
    mc = call and
    mc.getMethodName() = methodName and
    // The receiver is subsystem.method, where subsystem is on the forge object
    receiver = mc.getReceiver() and
    receiver.(PropAccess).getPropertyName() = subsystem and
    isForgeRef(receiver.(PropAccess).getBase())
  )
}

/**
 * Gets a MethodCallExpr for forge.X.Y.method() — three-level chain.
 * Example: forge.pki.rsa.generateKeyPair()
 *   sub1 = "pki", sub2 = "rsa", methodName = "generateKeyPair"
 *
 * Example: forge.md.sha256.create()
 *   sub1 = "md", sub2 = "sha256", methodName = "create"
 */
predicate isForgeDeepCall(InvokeExpr call, string sub1, string sub2, string methodName) {
  exists(MethodCallExpr mc, PropAccess mid, PropAccess base |
    mc = call and
    mc.getMethodName() = methodName and
    // receiver is sub2 on (sub1 on forge)
    mid = mc.getReceiver() and
    mid.(PropAccess).getPropertyName() = sub2 and
    base = mid.(PropAccess).getBase() and
    base.(PropAccess).getPropertyName() = sub1 and
    isForgeRef(base.(PropAccess).getBase())
  )
}

// =============================================================================
// Argument Value Resolution (Enhanced)
// =============================================================================

/**
 * Helper: holds when priority 1 (direct literal / local flow) succeeds.
 * Factored out to avoid repeating the pattern in every fallback guard.
 */
private predicate hasPriority1Result(InvokeExpr call, int argIndex) {
  exists(StringLiteral lit |
    call.getArgument(argIndex) = lit or
    call.getArgument(argIndex).flow().getALocalSource().asExpr() = lit
  )
}

/**
 * Gets the string value of the argument at argIndex, lowercased.
 *
 * Resolution strategies, tried in priority order:
 *   P1: direct string literal or local-flow variable assignment.
 *   P2: same-file object-property name heuristic.
 *   P3: forEach/map array-iteration heuristic.
 *   P4: simple template literal resolution.
 *   P5: ternary/conditional — extracts BOTH branches.
 *   P6: object map value enumeration — enumerates all string values in a map.
 *   P7: function default parameter values.
 *   P8: cross-function call-site argument tracking.
 *   P9: TypeScript enum / compiled enum member access.
 *
 * Lower-priority strategies only fire when all higher-priority ones fail,
 * preventing duplicates and ensuring the most precise result wins.
 */
string getArgValue(InvokeExpr call, int argIndex) {
  // Priority 1: direct literal or local-flow assignment
  hasPriority1Result(call, argIndex) and
  exists(StringLiteral lit |
    (call.getArgument(argIndex) = lit or
     call.getArgument(argIndex).flow().getALocalSource().asExpr() = lit) and
    result = lit.getValue().toLowerCase()
  )
  or
  // Priority 2: object-property name heuristic
  not hasPriority1Result(call, argIndex) and
  result = getArgValueByPropertyHeuristic(call, argIndex)
  or
  // Priority 3: array-iteration callback heuristic
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  result = getArgValueByArrayIterationHeuristic(call, argIndex)
  or
  // Priority 4: simple template literal
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  not exists(getArgValueByArrayIterationHeuristic(call, argIndex)) and
  result = resolveSimpleTemplateLiteral(call.getArgument(argIndex)).toLowerCase()
  or
  // Priority 5: ternary / conditional expression
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  not exists(getArgValueByArrayIterationHeuristic(call, argIndex)) and
  not exists(resolveSimpleTemplateLiteral(call.getArgument(argIndex))) and
  result = getArgValueByConditional(call, argIndex)
  or
  // Priority 6: object map value enumeration
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  not exists(getArgValueByArrayIterationHeuristic(call, argIndex)) and
  not exists(resolveSimpleTemplateLiteral(call.getArgument(argIndex))) and
  not exists(getArgValueByConditional(call, argIndex)) and
  result = getArgValueByObjectMapEnum(call, argIndex)
  or
  // Priority 7: function default parameter value
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  not exists(getArgValueByArrayIterationHeuristic(call, argIndex)) and
  not exists(resolveSimpleTemplateLiteral(call.getArgument(argIndex))) and
  not exists(getArgValueByConditional(call, argIndex)) and
  not exists(getArgValueByObjectMapEnum(call, argIndex)) and
  result = getArgValueByDefaultParam(call, argIndex)
  or
  // Priority 8: cross-function call-site argument tracking
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  not exists(getArgValueByArrayIterationHeuristic(call, argIndex)) and
  not exists(resolveSimpleTemplateLiteral(call.getArgument(argIndex))) and
  not exists(getArgValueByConditional(call, argIndex)) and
  not exists(getArgValueByObjectMapEnum(call, argIndex)) and
  not exists(getArgValueByDefaultParam(call, argIndex)) and
  result = getArgValueByCallSiteTracking(call, argIndex)
  or
  // Priority 9: TypeScript compiled enum member access
  not hasPriority1Result(call, argIndex) and
  not exists(getArgValueByPropertyHeuristic(call, argIndex)) and
  not exists(getArgValueByArrayIterationHeuristic(call, argIndex)) and
  not exists(resolveSimpleTemplateLiteral(call.getArgument(argIndex))) and
  not exists(getArgValueByConditional(call, argIndex)) and
  not exists(getArgValueByObjectMapEnum(call, argIndex)) and
  not exists(getArgValueByDefaultParam(call, argIndex)) and
  not exists(getArgValueByCallSiteTracking(call, argIndex)) and
  result = getArgValueByEnumAccess(call, argIndex)
}

// ---------------------------------------------------------------------------
// P2: Object-property name heuristic (original)
// ---------------------------------------------------------------------------

/**
 * Heuristic: finds algorithm strings passed indirectly via object properties
 * in the same file. The variable name used as the argument must match a
 * property name in an object literal in the same file.
 *
 * Example:
 *   const configs = [{ name: 'aes-128-cbc' }];
 *   configs.forEach(({ name }) => crypto.createCipheriv(name, key, iv));
 */
string getArgValueByPropertyHeuristic(InvokeExpr call, int argIndex) {
  exists(ObjectExpr obj, Property p, string varName |
    varName = call.getArgument(argIndex).(VarRef).getName() and
    obj.getFile() = call.getFile() and
    p = obj.getPropertyByName(varName) and
    result = p.getInit().(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// P3: Array iteration callback heuristic (original)
// ---------------------------------------------------------------------------

/**
 * Heuristic: finds string values passed through array iteration callbacks.
 *
 * Example:
 *   ['ed25519', 'ed448'].forEach(type => {
 *     crypto.generateKeyPairSync(type);
 *   });
 */
string getArgValueByArrayIterationHeuristic(InvokeExpr call, int argIndex) {
  exists(
    MethodCallExpr forEachCall, ArrayExpr arr, Function callback,
    SimpleParameter param, string paramName
  |
    forEachCall.getMethodName() = ["forEach", "map", "filter", "some", "every", "find"] and
    forEachCall.getReceiver().flow().getALocalSource().asExpr() = arr and
    callback = forEachCall.getArgument(0) and
    param = callback.getParameter(0) and
    paramName = param.getName() and
    call.getArgument(argIndex).(VarRef).getName() = paramName and
    call.getEnclosingFunction() = callback and
    result = arr.getAnElement().(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// P5: Ternary / conditional expression
// ---------------------------------------------------------------------------

/**
 * Resolves both branches of a ternary/conditional expression used as an
 * algorithm argument. Reports BOTH possible values.
 *
 * Handles:
 *   const algo = strong ? 'sha512' : 'sha256';
 *   crypto.createHash(algo);
 *
 * Also handles:
 *   crypto.createHash(flag ? 'sha512' : 'sha256');
 */
string getArgValueByConditional(InvokeExpr call, int argIndex) {
  exists(ConditionalExpr cond |
    // The conditional is the argument itself, or flows to it via a variable
    (
      call.getArgument(argIndex) = cond
      or
      call.getArgument(argIndex).flow().getALocalSource().asExpr() = cond
    ) and
    (
      result = cond.getConsequent().(StringLiteral).getValue().toLowerCase()
      or
      result = cond.getAlternate().(StringLiteral).getValue().toLowerCase()
    )
  )
  or
  // Also handle logical OR fallback: process.env.ALGO || 'sha256'
  exists(LogOrExpr orExpr |
    (
      call.getArgument(argIndex) = orExpr
      or
      call.getArgument(argIndex).flow().getALocalSource().asExpr() = orExpr
    ) and
    result = orExpr.getRightOperand().(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// P6: Object map value enumeration
// ---------------------------------------------------------------------------

/**
 * When an argument is a property access on an object literal (map/dictionary),
 * enumerates all string values in that object.
 *
 * Handles:
 *   const ALGO_MAP = { fast: 'md5', secure: 'sha256', paranoid: 'sha512' };
 *   crypto.createHash(ALGO_MAP[level]);      // dynamic index
 *   crypto.createHash(ALGO_MAP.secure);      // static property access
 *
 * Also handles:
 *   const ALGO_REGISTRY = { default: 'sha256', secure: 'sha512' };
 *   crypto.createHash(ALGO_REGISTRY[key]);
 */
string getArgValueByObjectMapEnum(InvokeExpr call, int argIndex) {
  exists(Expr arg, ObjectExpr obj |
    arg = call.getArgument(argIndex) and
    (
      // Dynamic index: ALGO_MAP[variable]
      exists(IndexExpr idx |
        arg = idx and
        idx.getBase().flow().getALocalSource().asExpr() = obj and
        obj.getFile() = call.getFile()
      )
      or
      // Static property: ALGO_MAP.secure — where the base flows from an object literal
      exists(PropAccess pa |
        arg = pa and
        pa.getBase().flow().getALocalSource().asExpr() = obj and
        obj.getFile() = call.getFile()
      )
      or
      // Via variable: const x = ALGO_MAP[y]; crypto.createHash(x);
      exists(IndexExpr idx |
        arg.flow().getALocalSource().asExpr() = idx and
        idx.getBase().flow().getALocalSource().asExpr() = obj and
        obj.getFile() = call.getFile()
      )
    ) and
    // Enumerate all string values in the object
    exists(Property p |
      p = obj.getAProperty() and
      result = p.getInit().(StringLiteral).getValue().toLowerCase()
    )
  )
}

// ---------------------------------------------------------------------------
// P7: Function default parameter values
// ---------------------------------------------------------------------------

/**
 * When the argument to the crypto call is a function parameter, extracts
 * the default value of that parameter (if it is a string literal).
 *
 * Handles:
 *   function hash(data, algorithm = 'sha256') {
 *     return crypto.createHash(algorithm).update(data).digest('hex');
 *   }
 *
 * Also handles:
 *   class EncryptionService {
 *     constructor(algorithm = 'aes-256-gcm') {
 *       this.algo = algorithm;
 *     }
 *     encrypt(data) { crypto.createCipheriv(this.algo, ...) }
 *   }
 *   (resolves the constructor default, though this.algo itself is not tracked)
 */
string getArgValueByDefaultParam(InvokeExpr call, int argIndex) {
  exists(Function fn, SimpleParameter param, string paramName |
    paramName = call.getArgument(argIndex).(VarRef).getName() and
    fn = call.getEnclosingFunction() and
    param = fn.getAParameter() and
    param.getName() = paramName and
    result = param.getDefault().(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// P8: Cross-function call-site argument tracking
// ---------------------------------------------------------------------------

/**
 * When a crypto call is inside a wrapper function and the algorithm argument
 * is a parameter of that function, finds string literals passed at call sites
 * of the wrapper function.
 *
 * Handles:
 *   function hashData(data, algo) {
 *     return crypto.createHash(algo).update(data).digest('hex');
 *   }
 *   hashData('data', 'sha256');   ← this string is resolved
 *   hashData('data', 'md5');      ← and this one too
 *
 * Limited to ONE level of indirection (no transitive call chains).
 * Limited to same-file call sites to keep evaluation fast.
 */
string getArgValueByCallSiteTracking(InvokeExpr call, int argIndex) {
  exists(
    Function wrapper, SimpleParameter param, int paramIndex,
    InvokeExpr callSite
  |
    // The crypto call's argument is a parameter of the enclosing function
    param.getName() = call.getArgument(argIndex).(VarRef).getName() and
    wrapper = call.getEnclosingFunction() and
    param = wrapper.getParameter(paramIndex) and
    // Find call sites of this wrapper function in the same file
    callSite.getFile() = call.getFile() and
    (
      // Direct call by name: hashData('data', 'sha256')
      callSite.getCalleeName() = wrapper.getName() and
      callSite.getFile() = wrapper.getFile()
      or
      // Call via variable: const fn = hashData; fn('data', 'sha256')
      callSite.getCallee().flow().getALocalSource().asExpr() = wrapper
    ) and
    // Extract the literal argument at the corresponding position
    result = callSite.getArgument(paramIndex).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// P9: TypeScript compiled enum / object constant member access
// ---------------------------------------------------------------------------

/**
 * Resolves values from compiled TypeScript enums and constant objects
 * accessed via dot notation.
 *
 * Handles compiled TS enums (which become self-executing IIFEs that assign
 * to an object), AND simple constant objects:
 *
 *   // Compiled enum:
 *   var HashAlgorithm;
 *   (function(HashAlgorithm) {
 *     HashAlgorithm["SHA256"] = "sha256";
 *   })(HashAlgorithm || (HashAlgorithm = {}));
 *   crypto.createHash(HashAlgorithm.SHA256);
 *
 *   // Simple constant object:
 *   const CipherMode = { AES_256_GCM: 'aes-256-gcm', AES_128_CBC: 'aes-128-cbc' };
 *   crypto.createCipheriv(CipherMode.AES_256_GCM, key, iv);
 *
 * Works by: when the argument is a PropAccess (X.Y), find any assignment
 * X["Y"] = "value" or X.Y = "value" in the same file, or an object literal
 * assigned to X with a property Y.
 */
string getArgValueByEnumAccess(InvokeExpr call, int argIndex) {
  exists(PropAccess pa, string objName, string propName |
    pa = call.getArgument(argIndex) and
    propName = pa.getPropertyName() and
    objName = pa.getBase().(VarRef).getName() and
    pa.getFile() = call.getFile() and
    (
      // Pattern 1: Assignment like HashAlgorithm["SHA256"] = "sha256"
      // or HashAlgorithm.SHA256 = "sha256"
      exists(AssignExpr assign, IndexExpr idx |
        assign.getFile() = call.getFile() and
        idx = assign.getLhs() and
        idx.getBase().(VarRef).getName() = objName and
        idx.getIndex().(StringLiteral).getValue() = propName and
        result = assign.getRhs().(StringLiteral).getValue().toLowerCase()
      )
      or
      // Pattern 2: Object literal: const X = { Y: 'value' }
      exists(ObjectExpr obj |
        obj.getFile() = call.getFile() and
        // The object is assigned to a variable with the same name
        exists(VariableDeclarator vd |
          vd.getBindingPattern().(VarDecl).getName() = objName and
          vd.getInit() = obj
        ) and
        result = obj.getPropertyByName(propName).getInit().(StringLiteral).getValue().toLowerCase()
      )
    )
  )
}

/**
 * Resolves simple template literals with exactly one substitution that is
 * a string or number literal.
 *
 * Handles: `sha${256}` → "sha256"
 *
 * Uses getElement(i) which is the TemplateLiteral-specific API for accessing
 * the alternating TemplateElement/expression children.
 *
 * NOTE: If this predicate fails to compile on your CodeQL version,
 * you can safely delete it AND remove the Priority 4 block from getArgValue.
 * The "unresolved" fallback in NodeCrypto.ql will catch any calls where the
 * algorithm cannot be statically resolved. Template literal algorithm names
 * are a rare edge case.
 */
string resolveSimpleTemplateLiteral(Expr e) {
  exists(TemplateLiteral tl, TemplateElement prefix, Expr sub, TemplateElement suffix |
    (e = tl or e.flow().getALocalSource().asExpr() = tl) and
    // Get the three elements: static-part, substitution, static-part
    prefix = tl.getElement(0) and
    sub = tl.getElement(1) and
    suffix = tl.getElement(2) and
    // Ensure the substitution is a resolvable literal (not another template or variable)
    (sub instanceof StringLiteral or sub instanceof NumberLiteral) and
    result = prefix.getValue() + sub.(Literal).getValue() + suffix.getValue()
  )
}

// =============================================================================
// WebCrypto Helpers
// =============================================================================

/**
 * Gets the algorithm name from a WebCrypto AlgorithmIdentifier.
 * Handles:
 *   1. Direct string: subtle.digest('SHA-256', ...)
 *   2. Direct object: subtle.digest({ name: 'SHA-256' }, ...)
 *   3. String via local flow: const a = 'SHA-256'; subtle.digest(a, ...)
 *   4. Object via local flow: const p = { name: 'SHA-256' }; subtle.digest(p, ...)
 *   5. String via variable name lookup: const digestAlgo = 'SHA-256'; subtle.digest(digestAlgo, ...)
 *   6. Object via variable name lookup: const params = { name: 'SHA-384' }; subtle.digest(params, ...)
 *
 * Strategies 5+6 use the same VariableDeclarator name-matching pattern that
 * works in the P9 enum resolution. No flow() guards needed — if strategies
 * 1-4 also match, results are deduplicated automatically by CodeQL.
 */
string getWebCryptoAlgoName(Expr arg) {
  // Strategy 1+3: direct string literal or via local flow
  exists(StringLiteral lit |
    (arg = lit or arg.flow().getALocalSource().asExpr() = lit) and
    result = lit.getValue().toUpperCase()
  )
  or
  // Strategy 2+4: direct object literal or via local flow
  exists(ObjectExpr obj, Property p |
    (arg = obj or arg.flow().getALocalSource().asExpr() = obj) and
    p = obj.getPropertyByName("name") and
    result = p.getInit().(StringLiteral).getValue().toUpperCase()
  )
  or
  // Strategy 5: VarRef → VariableDeclarator name lookup → StringLiteral init
  exists(VariableDeclarator decl |
    decl.getBindingPattern().(VarDecl).getName() = arg.(VarRef).getName() and
    decl.getFile() = arg.getFile() and
    result = decl.getInit().(StringLiteral).getValue().toUpperCase()
  )
  or
  // Strategy 6: VarRef → VariableDeclarator name lookup → ObjectExpr init with "name" property
  exists(VariableDeclarator decl, Property p |
    decl.getBindingPattern().(VarDecl).getName() = arg.(VarRef).getName() and
    decl.getFile() = arg.getFile() and
    p = decl.getInit().(ObjectExpr).getPropertyByName("name") and
    result = p.getInit().(StringLiteral).getValue().toUpperCase()
  )
}

/**
 * Enhanced version of getWebCryptoAlgoName that falls back to getArgValue's
 * multi-tier resolution (ternary, object map, default params, call-site
 * tracking, enum access) when the direct flow-based approach fails.
 *
 * This is called from WebCrypto.ql to resolve algorithm names that are
 * passed through variables, conditionals, or config objects.
 */
string getWebCryptoAlgoNameFull(InvokeExpr call, int argIndex) {
  // First try the direct WebCrypto-specific resolution (includes name lookup)
  result = getWebCryptoAlgoName(call.getArgument(argIndex))
  or
  // Fallback: use getArgValue (which has 9 resolution tiers) and uppercase it.
  // Only fires when the WebCrypto-specific resolution returned nothing.
  not exists(getWebCryptoAlgoName(call.getArgument(argIndex))) and
  result = getArgValue(call, argIndex).toUpperCase()
}

/**
 * Holds if the call is on a receiver named "subtle" or a property chain ending in ".subtle".
 */
predicate isSubtleCall(InvokeExpr call) {
  exists(MethodCallExpr mc | mc = call |
    mc.getReceiver().(VarRef).getName() = "subtle"
    or
    mc.getReceiver().(PropAccess).getPropertyName() = "subtle"
  )
}

/**
 * Holds if the given file imports the `webcrypto-shim` polyfill package.
 */
predicate fileUsesWebCryptoShim(File f) {
  exists(DataFlow::Node mod |
    mod = DataFlow::moduleImport("webcrypto-shim") and
    mod.getFile() = f
  )
}

/**
 * Returns "webcrypto-shim" if the file imports the shim, otherwise "webcrypto".
 */
string webCryptoApi(InvokeExpr call) {
  if fileUsesWebCryptoShim(call.getFile())
  then result = "webcrypto-shim"
  else result = "webcrypto"
}

// =============================================================================
// Node.js Crypto Import Tracking
// =============================================================================

/**
 * Holds if `call` is a method call on something that is (or flows from) an import
 * of the `crypto` module. This is stronger than just checking the receiver name.
 *
 * Covers:
 *   const crypto = require('crypto'); crypto.createHash(...)
 *   const c = require('crypto'); c.createHash(...)
 *   import crypto from 'crypto'; crypto.createHash(...)
 *   import * as crypto from 'node:crypto'; crypto.createHash(...)
 */
predicate isNodeCryptoMethodCall(InvokeExpr call, string methodName) {
  call.getCalleeName() = methodName and
  call instanceof MethodCallExpr and
  exists(DataFlow::SourceNode mod |
    (mod = DataFlow::moduleImport("crypto") or mod = DataFlow::moduleImport("node:crypto")) and
    call.(MethodCallExpr).getReceiver().flow().getALocalSource() = mod
  )
}

/**
 * Holds if `call` is a bare (non-method) call to a function destructured from the crypto module.
 *
 * Covers:
 *   const { createHash } = require('crypto'); createHash(...)
 *   import { createHash } from 'crypto'; createHash(...)
 *   const { createHash: myHash } = require('crypto'); myHash(...)  ← renamed
 */
predicate isDestructuredCryptoCall(InvokeExpr call, string functionName) {
  not call instanceof MethodCallExpr and
  exists(DataFlow::SourceNode member |
    (
      member = DataFlow::moduleMember("crypto", functionName) or
      member = DataFlow::moduleMember("node:crypto", functionName)
    ) and
    call.getCallee().flow().getALocalSource() = member
  )
}

/**
 * Holds if `call` is an aliased reference to a crypto module method.
 *
 * Covers:
 *   const hashFn = crypto.createHash; hashFn('sha256');
 *   const enc = crypto.createCipheriv; enc('aes-256-cbc', key, iv);
 */
predicate isAliasedCryptoCall(InvokeExpr call, string functionName) {
  not call instanceof MethodCallExpr and
  exists(DataFlow::SourceNode mod, DataFlow::SourceNode methodRef |
    (mod = DataFlow::moduleImport("crypto") or mod = DataFlow::moduleImport("node:crypto")) and
    methodRef = mod.getAPropertyRead(functionName) and
    call.getCallee().flow().getALocalSource() = methodRef
  )
}

/**
 * Holds if `call` is plausibly a call to `functionName` from node:crypto.
 * Combines import-tracked calls, destructured calls, aliased calls,
 * and the original callee-name heuristic (for cases where import tracking fails).
 */
predicate isNodeCryptoCall(InvokeExpr call, string functionName) {
  isNodeCryptoMethodCall(call, functionName)
  or
  isDestructuredCryptoCall(call, functionName)
  or
  isAliasedCryptoCall(call, functionName)
  or
  // Fallback heuristic: callee name matches and it's either a method call
  // on something named "crypto" or a bare call (not on a receiver)
  (
    call.getCalleeName() = functionName and
    not isNodeCryptoMethodCall(call, _) and
    not isDestructuredCryptoCall(call, _) and
    not isAliasedCryptoCall(call, _) and
    (
      not call instanceof MethodCallExpr
      or
      call.(MethodCallExpr).getReceiver().(VarRef).getName() = "crypto"
      or
      call.(MethodCallExpr).getReceiver().(PropAccess).getPropertyName() = "crypto"
    )
  )
}

// =============================================================================
// RSA Padding Detection (for publicEncrypt/privateDecrypt fix)
// =============================================================================

/**
 * Gets the padding mode string for an RSA encryption call.
 * Examines the key/options argument for a `padding` property referencing
 * crypto.constants.* values.
 */
string getRsaPadding(InvokeExpr call) {
  exists(ObjectExpr opts, PropAccess paddingAccess |
    opts = call.getArgument(0) and
    paddingAccess = opts.getPropertyByName("padding").getInit() and
    (
      (paddingAccess.getPropertyName() = "RSA_PKCS1_OAEP_PADDING" and result = "rsa-oaep")
      or
      (paddingAccess.getPropertyName() = "RSA_PKCS1_PADDING" and result = "rsa-pkcs1v15")
      or
      (paddingAccess.getPropertyName() = "RSA_PKCS1_PSS_PADDING" and result = "rsa-pss")
      or
      (paddingAccess.getPropertyName() = "RSA_NO_PADDING" and result = "rsa-no-padding")
    )
  )
}

// =============================================================================
// Options-Object Algorithm Extraction
// =============================================================================

/**
 * Gets the string value of a named property in an options object argument.
 * Useful for libraries like jsonwebtoken: jwt.sign(payload, key, { algorithm: 'RS256' })
 */
string getOptionsProperty(InvokeExpr call, int argIndex, string propertyName) {
  exists(ObjectExpr opts, Property p |
    (call.getArgument(argIndex) = opts or
     call.getArgument(argIndex).flow().getALocalSource().asExpr() = opts) and
    p = opts.getPropertyByName(propertyName) and
    result = p.getInit().(StringLiteral).getValue()
  )
}

/**
 * Gets the string value of a nested property like { header: { alg: 'RS256' } }.
 */
string getNestedOptionsProperty(InvokeExpr call, int argIndex, string outerProp, string innerProp) {
  exists(ObjectExpr outerObj, ObjectExpr innerObj |
    (call.getArgument(argIndex) = outerObj or
     call.getArgument(argIndex).flow().getALocalSource().asExpr() = outerObj) and
    (outerObj.getPropertyByName(outerProp).getInit() = innerObj or
     outerObj.getPropertyByName(outerProp).getInit().flow().getALocalSource().asExpr() = innerObj) and
    result = innerObj.getPropertyByName(innerProp).getInit().(StringLiteral).getValue()
  )
}

/**
 * Gets a PropAccess property name from an options object.
 * For patterns like: { mode: CryptoJS.mode.CBC } → "CBC"
 * Or: { hasher: CryptoJS.algo.SHA256 } → "SHA256"
 */
string getOptionsPropAccessName(InvokeExpr call, int argIndex, string propertyName) {
  exists(ObjectExpr opts |
    (call.getArgument(argIndex) = opts or
     call.getArgument(argIndex).flow().getALocalSource().asExpr() = opts) and
    result = opts.getPropertyByName(propertyName).getInit().(PropAccess).getPropertyName()
  )
}
