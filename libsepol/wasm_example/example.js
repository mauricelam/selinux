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
