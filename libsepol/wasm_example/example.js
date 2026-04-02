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
