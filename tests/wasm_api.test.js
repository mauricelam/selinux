const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");

const libsepolFactory = require("../dist/libsepol_browser.js");

const SAMPLE_CIL = `(user user_u)
(role role_r)
(type type_t)
(typeattribute attr_t)
(userrole user_u role_r)
(roletype role_r type_t)
(class class_t (perm_p perm_q))
(classorder (class_t))
(sid sid_s)
(sidorder (sid_s))
(sensitivity s0)
(sensitivityorder (s0))
(level l0 (s0))
(levelrange r0 (l0 l0))
(userlevel user_u l0)
(userrange user_u r0)
(sidcontext sid_s (user_u role_r type_t r0))
(allow type_t self (class_t (perm_p)))
(boolean test_bool true)
(mls true)`;

const SYM_CLASSES = 1;
const SYM_ROLES = 2;
const SYM_TYPES = 3;
const SYM_USERS = 4;
const SYM_BOOLS = 5;
const AVTAB_ALLOWED = 0x0001;

test.describe("SELinux WASM Module API Tests", () => {
  let Module;

  test.before(async () => {
    Module = await libsepolFactory({
      locateFile: (filename) => {
        if (filename.endsWith(".wasm")) {
          return path.join(__dirname, "../dist/", filename);
        }
        return filename;
      },
    });
    assert.ok(Module, "WASM module should be loaded");
  });

  test("sepol_check_context checks context string format", () => {
    const sepol_check_context = Module.cwrap("sepol_check_context", "number", ["string"]);
    assert.strictEqual(typeof sepol_check_context, "function");

    // Invalid context string should return non-zero (error)
    const invalidResult = sepol_check_context("invalid_context_string");
    assert.notStrictEqual(invalidResult, 0);
  });

  test("sepol_compile_cil_to_binary compiles CIL to binary policy", () => {
    const encoder = new TextEncoder();
    const cilBytes = encoder.encode(SAMPLE_CIL);
    const cilPtr = Module._malloc(cilBytes.length);
    Module.HEAPU8.set(cilBytes, cilPtr);

    const outDataPtrPtr = Module._malloc(4);
    const outSizePtr = Module._malloc(4);

    try {
      const result = Module.ccall(
        "sepol_compile_cil_to_binary",
        "number",
        ["number", "number", "number", "number"],
        [cilPtr, cilBytes.length, outDataPtrPtr, outSizePtr]
      );
      assert.strictEqual(result, 0, "CIL compilation should return 0 on success");

      const outDataPtr = Module.getValue(outDataPtrPtr, "i32");
      const outSize = Module.getValue(outSizePtr, "i32");
      assert.ok(outSize > 0, "Binary policy size should be greater than 0");
      assert.ok(outDataPtr !== 0, "Binary policy pointer should be non-null");

      const binaryPolicy = new Uint8Array(Module.HEAPU8.buffer, outDataPtr, outSize).slice();
      assert.strictEqual(binaryPolicy.length, outSize);

      Module._free(outDataPtr);
    } finally {
      Module._free(cilPtr);
      Module._free(outDataPtrPtr);
      Module._free(outSizePtr);
    }
  });

  test("sepol_compile_cil_to_binary handles invalid CIL", () => {
    const invalidCil = "(invalid_cil_syntax)";
    const encoder = new TextEncoder();
    const cilBytes = encoder.encode(invalidCil);
    const cilPtr = Module._malloc(cilBytes.length);
    Module.HEAPU8.set(cilBytes, cilPtr);

    const outDataPtrPtr = Module._malloc(4);
    const outSizePtr = Module._malloc(4);

    try {
      const result = Module.ccall(
        "sepol_compile_cil_to_binary",
        "number",
        ["number", "number", "number", "number"],
        [cilPtr, cilBytes.length, outDataPtrPtr, outSizePtr]
      );
      assert.notStrictEqual(result, 0, "Invalid CIL compilation should return non-zero code");
    } finally {
      Module._free(cilPtr);
      Module._free(outDataPtrPtr);
      Module._free(outSizePtr);
    }
  });

  test("sepol_get_cil_ast retrieves resolved AST string", () => {
    const encoder = new TextEncoder();
    const cilBytes = encoder.encode(SAMPLE_CIL);
    const cilPtr = Module._malloc(cilBytes.length);
    Module.HEAPU8.set(cilBytes, cilPtr);

    const outAstPtrPtr = Module._malloc(4);
    const outSizePtr = Module._malloc(4);

    try {
      const result = Module.ccall(
        "sepol_get_cil_ast",
        "number",
        ["number", "number", "number", "number"],
        [cilPtr, cilBytes.length, outAstPtrPtr, outSizePtr]
      );
      assert.strictEqual(result, 0, "sepol_get_cil_ast should return 0 on success");

      const outAstPtr = Module.getValue(outAstPtrPtr, "i32");
      const outSize = Module.getValue(outSizePtr, "i32");
      assert.ok(outSize > 0, "AST string size should be greater than 0");

      const astBytes = new Uint8Array(Module.HEAPU8.buffer, outAstPtr, outSize);
      const astString = new TextDecoder().decode(astBytes);
      assert.ok(astString.includes("user_u"), "AST string should contain CIL symbols");

      Module._free(outAstPtr);
    } finally {
      Module._free(cilPtr);
      Module._free(outAstPtrPtr);
      Module._free(outSizePtr);
    }
  });

  test("Policy Analysis Bridge APIs (api_*) inspect compiled binary policy", () => {
    // 1. Compile CIL to binary
    const encoder = new TextEncoder();
    const cilBytes = encoder.encode(SAMPLE_CIL);
    const cilPtr = Module._malloc(cilBytes.length);
    Module.HEAPU8.set(cilBytes, cilPtr);

    const outDataPtrPtr = Module._malloc(4);
    const outSizePtr = Module._malloc(4);

    let binaryPolicy;
    try {
      const res = Module.ccall(
        "sepol_compile_cil_to_binary",
        "number",
        ["number", "number", "number", "number"],
        [cilPtr, cilBytes.length, outDataPtrPtr, outSizePtr]
      );
      assert.strictEqual(res, 0);

      const outDataPtr = Module.getValue(outDataPtrPtr, "i32");
      const outSize = Module.getValue(outSizePtr, "i32");
      binaryPolicy = new Uint8Array(Module.HEAPU8.buffer, outDataPtr, outSize).slice();
      Module._free(outDataPtr);
    } finally {
      Module._free(cilPtr);
      Module._free(outDataPtrPtr);
      Module._free(outSizePtr);
    }

    // 2. Load policy
    const policyBufPtr = Module._malloc(binaryPolicy.length);
    Module.HEAPU8.set(binaryPolicy, policyBufPtr);

    const handle = Module.ccall(
      "api_load_policy",
      "number",
      ["number", "number"],
      [policyBufPtr, binaryPolicy.length]
    );
    assert.ok(handle !== 0, "api_load_policy should return a valid non-zero handle");

    try {
      // api_get_version
      const version = Module.ccall("api_get_version", "number", ["number"], [handle]);
      assert.ok(version >= 30, `Policy version should be >= 30, got ${version}`);

      // api_get_symbol_count
      const classCount = Module.ccall("api_get_symbol_count", "number", ["number", "number"], [handle, SYM_CLASSES]);
      const roleCount = Module.ccall("api_get_symbol_count", "number", ["number", "number"], [handle, SYM_ROLES]);
      const typeCount = Module.ccall("api_get_symbol_count", "number", ["number", "number"], [handle, SYM_TYPES]);
      const userCount = Module.ccall("api_get_symbol_count", "number", ["number", "number"], [handle, SYM_USERS]);
      const boolCount = Module.ccall("api_get_symbol_count", "number", ["number", "number"], [handle, SYM_BOOLS]);

      assert.strictEqual(classCount, 1);
      assert.strictEqual(roleCount, 2); // object_r + role_r
      assert.strictEqual(typeCount, 1); // type_t
      assert.strictEqual(userCount, 1);
      assert.strictEqual(boolCount, 1);

      // api_get_symbol_name
      const type1Ptr = Module.ccall("api_get_symbol_name", "number", ["number", "number", "number"], [handle, SYM_TYPES, 1]);
      const type1Name = Module.UTF8ToString(type1Ptr);
      assert.strictEqual(type1Name, "type_t");

      // api_is_type_attribute
      const isAttr1 = Module.ccall("api_is_type_attribute", "number", ["number", "number"], [handle, 1]);
      assert.strictEqual(isAttr1, 0, "type_t should not be a type attribute");

      // api_get_boolean_state
      const boolState = Module.ccall("api_get_boolean_state", "number", ["number", "number"], [handle, 1]);
      assert.strictEqual(boolState, 1, "test_bool should have state 1 (true)");

      // api_get_rule_count
      const ruleCount = Module.ccall("api_get_rule_count", "number", ["number", "number"], [handle, AVTAB_ALLOWED]);
      assert.strictEqual(ruleCount, 1, "Should have 1 allowed rule");

      // api_get_rules (plain text query)
      const maxRules = 10;
      const rulesBufPtr = Module._malloc(maxRules * 16);
      const queryPtr = Module.allocateUTF8("type_t");

      const foundCount = Module.ccall(
        "api_get_rules",
        "number",
        ["number", "number", "number", "number", "number", "number"],
        [handle, rulesBufPtr, maxRules, queryPtr, 0, AVTAB_ALLOWED]
      );
      assert.strictEqual(foundCount, 1);

      const src = Module.getValue(rulesBufPtr, "i32");
      const tgt = Module.getValue(rulesBufPtr + 4, "i32");
      const cls = Module.getValue(rulesBufPtr + 8, "i32");
      const data = Module.getValue(rulesBufPtr + 12, "i32");

      assert.strictEqual(src, 1);
      assert.strictEqual(tgt, 1);
      assert.strictEqual(cls, 1);
      assert.ok(data > 0);

      // api_get_permissions & api_free_string
      const permPtr = Module.ccall(
        "api_get_permissions",
        "number",
        ["number", "number", "number"],
        [handle, cls, data]
      );
      assert.ok(permPtr !== 0);
      const permStr = Module.UTF8ToString(permPtr);
      assert.ok(permStr.includes("perm_p"));
      Module.ccall("api_free_string", null, ["number"], [permPtr]);

      Module._free(queryPtr);

      // api_get_rules (regex query)
      const regexQueryPtr = Module.allocateUTF8("type_.*");
      const regexFoundCount = Module.ccall(
        "api_get_rules",
        "number",
        ["number", "number", "number", "number", "number", "number"],
        [handle, rulesBufPtr, maxRules, regexQueryPtr, 1, AVTAB_ALLOWED]
      );
      assert.strictEqual(regexFoundCount, 1);
      Module._free(regexQueryPtr);

      Module._free(rulesBufPtr);
    } finally {
      Module.ccall("api_free_policy", null, ["number"], [handle]);
      Module._free(policyBufPtr);
    }
  });

  test("Low-level CIL and Policydb APIs", () => {
    // 1. cil_db_init, cil_add_file, cil_compile, cil_build_policydb, cil_db_destroy
    const dbPtrPtr = Module._malloc(4);
    Module.ccall("cil_db_init", "number", ["number"], [dbPtrPtr]);
    const dbPtr = Module.getValue(dbPtrPtr, "i32");
    assert.ok(dbPtr !== 0, "cil_db_init should initialize db pointer");

    const fileNamePtr = Module.allocateUTF8("test.cil");
    const cilSourcePtr = Module.allocateUTF8(SAMPLE_CIL);

    try {
      let rc = Module.ccall(
        "cil_add_file",
        "number",
        ["number", "number", "number", "number"],
        [dbPtr, fileNamePtr, cilSourcePtr, SAMPLE_CIL.length]
      );
      assert.strictEqual(rc, 0, "cil_add_file should return 0");

      rc = Module.ccall("cil_compile", "number", ["number"], [dbPtr]);
      assert.strictEqual(rc, 0, "cil_compile should return 0");

      const pdPtrPtr = Module._malloc(4);
      try {
        rc = Module.ccall("cil_build_policydb", "number", ["number", "number"], [dbPtr, pdPtrPtr]);
        assert.strictEqual(rc, 0, "cil_build_policydb should return 0");
        const pdPtr = Module.getValue(pdPtrPtr, "i32");
        assert.ok(pdPtr !== 0, "policydb pointer should be valid");

        Module.ccall("sepol_policydb_free", null, ["number"], [pdPtr]);
      } finally {
        Module._free(pdPtrPtr);
      }
    } finally {
      Module.ccall("cil_db_destroy", null, ["number"], [dbPtrPtr]);
      Module._free(dbPtrPtr);
      Module._free(fileNamePtr);
      Module._free(cilSourcePtr);
    }

    // 2. sepol_policydb_create / sepol_policydb_free
    const pdbPtrPtr = Module._malloc(4);
    try {
      const rc = Module.ccall("sepol_policydb_create", "number", ["number"], [pdbPtrPtr]);
      assert.strictEqual(rc, 0, "sepol_policydb_create should return 0");
      const pdbPtr = Module.getValue(pdbPtrPtr, "i32");
      assert.ok(pdbPtr !== 0, "created policydb pointer should be valid");

      Module.ccall("sepol_policydb_free", null, ["number"], [pdbPtr]);
    } finally {
      Module._free(pdbPtrPtr);
    }
  });
});
