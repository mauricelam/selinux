// Initialize libsepol module
let libsepolModule;

libsepol({
    locateFile: function(path, prefix) {
        if (path.endsWith('.wasm')) {
            return '../src/' + path;
        }
        return prefix + path;
    }
}).then(instance => {
    libsepolModule = instance;
    document.getElementById('output').innerText = 'libsepol initialized and ready.';
    console.log('libsepol loaded');
});

// Helper function to handle Uint8Array input and output for CIL compilation
function compileCilToBinary(cilSource) {
    if (!libsepolModule) {
        throw new Error('libsepol is not yet loaded');
    }

    // Allocate memory for the CIL source
    const encoder = new TextEncoder();
    const cilBytes = encoder.encode(cilSource);
    const cilSize = cilBytes.length;
    const cilPtr = libsepolModule._malloc(cilSize);
    libsepolModule.HEAPU8.set(cilBytes, cilPtr);

    // Allocate memory for the output pointer and size
    const outDataPtrPtr = libsepolModule._malloc(4); // 32-bit pointer
    const outSizePtr = libsepolModule._malloc(4);    // 32-bit size

    try {
        // Call the C function
        // int sepol_compile_cil_to_binary(const char *cil_data, size_t cil_size, char **out_data, size_t *out_size)
        const result = libsepolModule.ccall(
            'sepol_compile_cil_to_binary',
            'number',
            ['number', 'number', 'number', 'number'],
            [cilPtr, cilSize, outDataPtrPtr, outSizePtr]
        );

        if (result !== 0) {
            throw new Error(`CIL compilation failed with code: ${result}`);
        }

        // Get the output data pointer and size from the allocated memory
        const outDataPtr = libsepolModule.getValue(outDataPtrPtr, 'i32');
        const outSize = libsepolModule.getValue(outSizePtr, 'i32');

        // Copy the binary policy from WASM memory to a JS Uint8Array
        const binaryPolicy = new Uint8Array(libsepolModule.HEAPU8.buffer, outDataPtr, outSize).slice();

        // Free the output data buffer allocated in C
        libsepolModule._free(outDataPtr);

        return binaryPolicy;
    } finally {
        // Free the input and pointers allocated in JS
        libsepolModule._free(cilPtr);
        libsepolModule._free(outDataPtrPtr);
        libsepolModule._free(outSizePtr);
    }
}

// Helper function to retrieve the resolved CIL AST as a string
function getCilAst(cilSource) {
    if (!libsepolModule) {
        throw new Error('libsepol is not yet loaded');
    }

    // Allocate memory for the CIL source
    const encoder = new TextEncoder();
    const cilBytes = encoder.encode(cilSource);
    const cilSize = cilBytes.length;
    const cilPtr = libsepolModule._malloc(cilSize);
    libsepolModule.HEAPU8.set(cilBytes, cilPtr);

    // Allocate memory for the output pointer and size
    const outAstPtrPtr = libsepolModule._malloc(4); // 32-bit pointer
    const outSizePtr = libsepolModule._malloc(4);   // 32-bit size

    try {
        // Call the C function
        // int sepol_get_cil_ast(const char *cil_data, size_t cil_size, char **out_ast, size_t *out_size)
        const result = libsepolModule.ccall(
            'sepol_get_cil_ast',
            'number',
            ['number', 'number', 'number', 'number'],
            [cilPtr, cilSize, outAstPtrPtr, outSizePtr]
        );

        if (result !== 0) {
            throw new Error(`Getting CIL AST failed with code: ${result}`);
        }

        // Get the output string pointer and size from the allocated memory
        const outAstPtr = libsepolModule.getValue(outAstPtrPtr, 'i32');
        const outSize = libsepolModule.getValue(outSizePtr, 'i32');

        // Decipher the AST string from WASM memory
        const astBytes = new Uint8Array(libsepolModule.HEAPU8.buffer, outAstPtr, outSize);
        const astString = new TextDecoder().decode(astBytes);

        // Free the output string allocated in C
        libsepolModule._free(outAstPtr);

        return astString;
    } finally {
        // Free the input and pointers allocated in JS
        libsepolModule._free(cilPtr);
        libsepolModule._free(outAstPtrPtr);
        libsepolModule._free(outSizePtr);
    }
}

// Inspect a loaded binary policy using api_* bridge functions
function analyzeBinaryPolicy(binaryPolicy) {
    if (!libsepolModule) throw new Error('libsepol is not loaded');

    const dataPtr = libsepolModule._malloc(binaryPolicy.length);
    libsepolModule.HEAPU8.set(binaryPolicy, dataPtr);

    const handle = libsepolModule.ccall('api_load_policy', 'number', ['number', 'number'], [dataPtr, binaryPolicy.length]);
    if (!handle) {
        libsepolModule._free(dataPtr);
        throw new Error('Failed to load binary policy into policydb');
    }

    try {
        const version = libsepolModule.ccall('api_get_version', 'number', ['number'], [handle]);

        // Symbol table constants in libsepol
        const SYM_CLASSES = 1;
        const SYM_ROLES = 2;
        const SYM_TYPES = 3;
        const SYM_USERS = 4;
        const SYM_BOOLS = 5;

        const classCount = libsepolModule.ccall('api_get_symbol_count', 'number', ['number', 'number'], [handle, SYM_CLASSES]);
        const roleCount = libsepolModule.ccall('api_get_symbol_count', 'number', ['number', 'number'], [handle, SYM_ROLES]);
        const typeCount = libsepolModule.ccall('api_get_symbol_count', 'number', ['number', 'number'], [handle, SYM_TYPES]);
        const userCount = libsepolModule.ccall('api_get_symbol_count', 'number', ['number', 'number'], [handle, SYM_USERS]);
        const boolCount = libsepolModule.ccall('api_get_symbol_count', 'number', ['number', 'number'], [handle, SYM_BOOLS]);

        let output = `Policy Version: ${version}\n`;
        output += `Symbol Counts: Classes=${classCount}, Roles=${roleCount}, Types=${typeCount}, Users=${userCount}, Booleans=${boolCount}\n\n`;

        output += `Types & Attributes:\n`;
        for (let i = 1; i <= typeCount; i++) {
            const namePtr = libsepolModule.ccall('api_get_symbol_name', 'number', ['number', 'number', 'number'], [handle, SYM_TYPES, i]);
            const name = namePtr ? libsepolModule.UTF8ToString(namePtr) : 'unknown';
            const isAttr = libsepolModule.ccall('api_is_type_attribute', 'number', ['number', 'number'], [handle, i]);
            output += `  - Type [${i}]: ${name} (${isAttr === 1 ? 'Attribute' : 'Type'})\n`;
        }

        const AVTAB_ALLOWED = 0x0001;
        const ruleCount = libsepolModule.ccall('api_get_rule_count', 'number', ['number', 'number'], [handle, AVTAB_ALLOWED]);
        output += `\nAllowed Rules Count: ${ruleCount}\n`;

        return output;
    } finally {
        libsepolModule.ccall('api_free_policy', null, ['number'], [handle]);
        libsepolModule._free(dataPtr);
    }
}

// Search rules in a binary policy using api_get_rules and api_get_permissions
function searchRulesInPolicy(binaryPolicy, query, isRegex) {
    if (!libsepolModule) throw new Error('libsepol is not loaded');

    const dataPtr = libsepolModule._malloc(binaryPolicy.length);
    libsepolModule.HEAPU8.set(binaryPolicy, dataPtr);

    const handle = libsepolModule.ccall('api_load_policy', 'number', ['number', 'number'], [dataPtr, binaryPolicy.length]);
    if (!handle) {
        libsepolModule._free(dataPtr);
        throw new Error('Failed to load binary policy');
    }

    try {
        const AVTAB_ALLOWED = 0x0001;
        const maxRules = 100;
        const rulesBufferPtr = libsepolModule._malloc(maxRules * 16); // rule_info_t is 16 bytes

        const queryPtr = query ? libsepolModule.allocateUTF8(query) : 0;

        const count = libsepolModule.ccall(
            'api_get_rules',
            'number',
            ['number', 'number', 'number', 'number', 'number', 'number'],
            [handle, rulesBufferPtr, maxRules, queryPtr, isRegex ? 1 : 0, AVTAB_ALLOWED]
        );

        if (queryPtr) libsepolModule._free(queryPtr);

        let output = `Found ${count} matching AV rule(s):\n`;

        const SYM_CLASSES = 1;
        const SYM_TYPES = 3;

        for (let i = 0; i < count; i++) {
            const offset = rulesBufferPtr + i * 16;
            const src = libsepolModule.getValue(offset, 'i32');
            const tgt = libsepolModule.getValue(offset + 4, 'i32');
            const cls = libsepolModule.getValue(offset + 8, 'i32');
            const data = libsepolModule.getValue(offset + 12, 'i32');

            const srcPtr = libsepolModule.ccall('api_get_symbol_name', 'number', ['number', 'number', 'number'], [handle, SYM_TYPES, src]);
            const tgtPtr = libsepolModule.ccall('api_get_symbol_name', 'number', ['number', 'number', 'number'], [handle, SYM_TYPES, tgt]);
            const clsPtr = libsepolModule.ccall('api_get_symbol_name', 'number', ['number', 'number', 'number'], [handle, SYM_CLASSES, cls]);

            const srcName = srcPtr ? libsepolModule.UTF8ToString(srcPtr) : src;
            const tgtName = tgtPtr ? libsepolModule.UTF8ToString(tgtPtr) : tgt;
            const clsName = clsPtr ? libsepolModule.UTF8ToString(clsPtr) : cls;

            const permStrPtr = libsepolModule.ccall('api_get_permissions', 'number', ['number', 'number', 'number'], [handle, cls, data]);
            const permStr = permStrPtr ? libsepolModule.UTF8ToString(permStrPtr) : `0x${data.toString(16)}`;

            if (permStrPtr) {
                libsepolModule.ccall('api_free_string', null, ['number'], [permStrPtr]);
            }

            output += `  allow ${srcName} ${tgtName}:${clsName} { ${permStr.trim()} };\n`;
        }

        libsepolModule._free(rulesBufferPtr);
        return output;
    } finally {
        libsepolModule.ccall('api_free_policy', null, ['number'], [handle]);
        libsepolModule._free(dataPtr);
    }
}

document.getElementById('checkButton').addEventListener('click', () => {
    if (!libsepolModule) {
        alert('libsepol is not yet loaded');
        return;
    }

    const context = document.getElementById('contextInput').value;
    const outputDiv = document.getElementById('output');

    // Use cwrap to get the C function
    const sepol_check_context = libsepolModule.cwrap('sepol_check_context', 'number', ['string']);

    try {
        const result = sepol_check_context(context);
        if (result === 0) {
            outputDiv.innerHTML = `<span class="valid">SUCCESS:</span> "${context}" is a valid context format (Note: no policy loaded).`;
        } else {
            outputDiv.innerHTML = `<span class="invalid">FAILURE:</span> "${context}" is NOT a valid context format.`;
        }
    } catch (e) {
        outputDiv.innerText = 'Error: ' + e.message;
    }
});

document.getElementById('compileButton').addEventListener('click', () => {
    if (!libsepolModule) {
        alert('libsepol is not yet loaded');
        return;
    }

    const cilInput = document.getElementById('cilInput').value;
    const cilOutput = document.getElementById('cilOutput');
    const downloadArea = document.getElementById('downloadArea');
    downloadArea.innerHTML = '';

    try {
        const binaryPolicy = compileCilToBinary(cilInput);
        cilOutput.innerHTML = `<span class="valid">SUCCESS:</span> CIL compiled successfully to binary policy (${binaryPolicy.length} bytes).`;

        // Create a download link for the binary policy
        const blob = new Blob([binaryPolicy], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'policy.bin';
        a.innerText = 'Download Binary Policy (policy.bin)';
        a.style.display = 'block';
        downloadArea.appendChild(a);
    } catch (e) {
        console.error(e);
        cilOutput.innerHTML = `<span class="invalid">FAILURE:</span> ${e.message}`;
    }
});

document.getElementById('astButton').addEventListener('click', () => {
    if (!libsepolModule) {
        alert('libsepol is not yet loaded');
        return;
    }

    const cilInput = document.getElementById('cilInput').value;
    const astOutput = document.getElementById('astOutput');

    try {
        const astString = getCilAst(cilInput);
        astOutput.innerText = astString;
    } catch (e) {
        console.error(e);
        astOutput.innerHTML = `<span class="invalid">FAILURE:</span> ${e.message}`;
    }
});

document.getElementById('analyzeButton').addEventListener('click', () => {
    if (!libsepolModule) {
        alert('libsepol is not yet loaded');
        return;
    }

    const cilInput = document.getElementById('cilInput').value;
    const apiOutput = document.getElementById('apiOutput');

    try {
        const binaryPolicy = compileCilToBinary(cilInput);
        const analysis = analyzeBinaryPolicy(binaryPolicy);
        apiOutput.innerText = analysis;
    } catch (e) {
        console.error(e);
        apiOutput.innerHTML = `<span class="invalid">FAILURE:</span> ${e.message}`;
    }
});

document.getElementById('searchRulesButton').addEventListener('click', () => {
    if (!libsepolModule) {
        alert('libsepol is not yet loaded');
        return;
    }

    const cilInput = document.getElementById('cilInput').value;
    const query = document.getElementById('ruleSearchQuery').value;
    const apiOutput = document.getElementById('apiOutput');

    try {
        const binaryPolicy = compileCilToBinary(cilInput);
        const rulesOutput = searchRulesInPolicy(binaryPolicy, query, false);
        apiOutput.innerText = rulesOutput;
    } catch (e) {
        console.error(e);
        apiOutput.innerHTML = `<span class="invalid">FAILURE:</span> ${e.message}`;
    }
});
